//  When cursor is placed on a call to the RC4 deobfuscation function used throughout
//  Flare-On 6 "Help" challenge binaries, this script iterates attempts to decrypt the input buffer,
//  renaming the output variable with the plaintext result
//
//  "Inspired by" (code stolen from) MakeStackRefs.java and ShowCCalls.java scripts bundled
//  with Ghidra.
//@category Flare.2019

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FlareHelpDecryptRC4Call extends GhidraScript {
	static class RC4 {
		// Taken from https://stackoverflow.com/a/12290876/756104
		// Used because java security policy doesn't allow 32-bit RC4 keys (too small)
		private final byte[] S = new byte[256];
		private final byte[] T = new byte[256];
		private final int keylen;

		public RC4(final byte[] key) {
			if (key.length < 1 || key.length > 256) {
				throw new IllegalArgumentException(
						"key must be between 1 and 256 bytes");
			}
			keylen = key.length;
			for (int i = 0; i < 256; i++) {
				S[i] = (byte) i;
				T[i] = key[i % keylen];
			}
			int j = 0;
			byte tmp;
			for (int i = 0; i < 256; i++) {
				j = (j + S[i] + T[i]) & 0xFF;
				tmp = S[j];
				S[j] = S[i];
				S[i] = tmp;
			}
		}

		public byte[] encrypt(final byte[] plaintext) {
			final byte[] ciphertext = new byte[plaintext.length];
			int i = 0, j = 0, k, t;
			byte tmp;
			for (int counter = 0; counter < plaintext.length; counter++) {
				i = (i + 1) & 0xFF;
				j = (j + S[i]) & 0xFF;
				tmp = S[j];
				S[j] = S[i];
				S[i] = tmp;
				t = (S[i] + S[j]) & 0xFF;
				k = S[t];
				ciphertext[counter] = (byte) (plaintext[counter] ^ k);
			}
			return ciphertext;
		}

		public byte[] decrypt(final byte[] ciphertext) {
			return encrypt(ciphertext);
		}
	}

	Optional<Varnode> getStackRefVarnode(Varnode arrNode) {
		// Depending on the type def of the decryption function,
		// the array input node could be defined by a PTRSUB/PTRADD (&local_buf),
		// or a _cast_ of one
		Varnode n = arrNode;

		// Skip any casts
		for (int i = 0; i < 4 && n != null && n.getDef().getOpcode() == PcodeOp.CAST; ++i) {
			n = n.getDef().getInput(0);
		}

		if (n != null && n.getDef().getOpcode() == PcodeOp.PTRADD || n.getDef().getOpcode() == PcodeOp.PTRSUB) {
			return Optional.of(n);
		}

		return Optional.empty();
	}

	/**
	 * Takes a pair of input varnodes to the RC4 decryption routine (the key and
	 * keylength arguments, or ciphertext and ciphertext length) and creates/returns
	 * a variable in the function containing the call, which is a char[] of the
	 * appropriate length.
	 *
	 * @param sFrame StackFrame for the function containing the varnodes
	 * @param arrNode
	 * @param arrLenNode
	 * @return
	 */
	private Optional<Variable> makeStackArrayVariable(StackFrame sFrame, Varnode arrNode, Varnode arrLenNode) {
		if (!arrLenNode.isConstant()) {
			println("Invalid arrayLen varnode");
			return Optional.empty();
		}
		long arrLen = ((HighConstant) arrLenNode.getHigh()).getScalar().getValue();

		// Get the stack variable that corresponds to the array reference
		final Optional<Varnode> arrNodeDef = getStackRefVarnode(arrNode);
		Reference[] refs = arrNodeDef.map(n -> currentProgram.getReferenceManager()
				.getReferencesFrom(n.getPCAddress())).orElse(new Reference[0]);
		if (refs.length != 1 || !refs[0].isStackReference()) {
			println("Failed to fetch stack variable for varnode");
			return Optional.empty();
		}

		DataType dataType = new ArrayDataType(new CharDataType(), (int) arrLen, 1);
		StackReference arrRef = (StackReference) refs[0];
		Variable arrVar = sFrame.getVariableContaining(arrRef.getStackOffset());
		try {
			if (arrVar == null) {
				arrVar = sFrame.createVariable("local_" + (-arrRef.getStackOffset()), arrRef.getStackOffset(), dataType,
						SourceType.USER_DEFINED);
			} else {
				arrVar.setDataType(dataType, false, true, SourceType.USER_DEFINED);
			}
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
			return Optional.empty();
		}

		return Optional.of(arrVar);
	}

	private Optional<byte[]> getArrContents(HighFunction hf, Variable arrVar) {
		byte contents[] = new byte[arrVar.getDataType().getLength()];
		Set<Integer> idxSet = new HashSet<>();

		final ReferenceManager refMgr = currentProgram.getReferenceManager();
		Stream.of(refMgr.getReferencesTo(arrVar))
		.filter(r -> r instanceof StackReference && r.getReferenceType().equals(RefType.WRITE))
		.map(r -> (StackReference) r).forEach(r -> {
			int idx = r.getStackOffset() - arrVar.getStackOffset();
			Instruction instr = getInstructionAt(r.getFromAddress());
			if (instr.getNumOperands() == 2 && instr.getAddress(0) != null && instr.getScalar(1) != null) {
				if (idx < 0 || idx > contents.length) {
					printf("Ref at %s indexes out of bounds of stack array?\n", r.getFromAddress());
				} else {
					idxSet.add(idx);
					contents[idx] = (byte) (instr.getScalar(1).getValue() & 0xff);
				}
			}
		});

		if (idxSet.size() != contents.length) {
			printf("Can't determine values for all indices of %s\n", arrVar.getName());
			return Optional.empty();
		}

		return Optional.of(contents);
	}

	private byte[] rc4Decrypt(byte[] keyBytes, byte[] cipherText) {
		RC4 rc4 = new RC4(keyBytes);
		return rc4.decrypt(cipherText);
	}

	private void processCall(DecompInterface decomplib, Address addr) {
		final Function curFun = currentProgram.getFunctionManager().getFunctionContaining(addr);
		if (curFun == null) {
			println("Not in a function? Exiting");
			return;
		}

		final HighFunction highFun = decompileFunction(curFun, decomplib);
		if (highFun != null) {
			Iterator<PcodeOpAST> ops = highFun.getPcodeOps(addr);

			while (ops.hasNext() && !monitor.isCancelled()) {
				final PcodeOpAST currentOp = ops.next();

				if (currentOp.getOpcode() == PcodeOp.CALL) {
					Optional<Variable> keyVar = makeStackArrayVariable(
							curFun.getStackFrame(),
							currentOp.getInput(1),
							currentOp.getInput(2));
					Optional<Variable> ctextVar = makeStackArrayVariable(
							curFun.getStackFrame(),
							currentOp.getInput(3),
							currentOp.getInput(4));
					Optional<byte[]> keyBytes = keyVar.flatMap(v -> getArrContents(highFun, v));
					Optional<byte[]> ctextBytes = ctextVar.flatMap(v -> getArrContents(highFun, v));

					if (keyBytes.isPresent() && ctextBytes.isPresent()) {
						byte[] ptext = rc4Decrypt(keyBytes.get(), ctextBytes.get());

						try {
							String varName = null;
							// Hack: the wide strings in the flare binaries consist entirely of chars in the
							// ascii range, so last byte (upper 8 bits of last code unit) will be zero
							if (ptext.length >= 2 && ptext[ptext.length-1] == 0) {
								varName = "usz_" + new String(ptext, "UTF-16LE");
							} else {
								varName = "sz_" + new String(ptext, "UTF-8");
							}
							ctextVar.get().setName(varName, SourceType.USER_DEFINED);
						} catch (DuplicateNameException | InvalidInputException | UnsupportedEncodingException e) {
							e.printStackTrace();
						}
					}
				}
			}
		}
	}

	@Override
	public void run() throws Exception {
		final DecompInterface decomplib = setUpDecompiler(currentProgram);

		if (!decomplib.openProgram(currentProgram)) {
			println("Decompile Error: " + decomplib.getLastMessage());
			return;
		}

		processCall(decomplib, currentAddress);
	}

	// Decompiler stuff
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public HighFunction decompileFunction(Function f, DecompInterface decompInterface) {
		try {
			DecompileResults decompRes = decompInterface.decompileFunction(f,
					decompInterface.getOptions().getDefaultTimeout(), monitor);

			return decompRes.getHighFunction();
		} catch (Exception exc) {
			exc.printStackTrace();
			return null;
		}
	}
}
