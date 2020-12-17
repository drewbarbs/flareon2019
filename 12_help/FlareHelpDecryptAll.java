//When cursor is placed on a call to the RC4 deobfuscation function used throughout the Flare-On 6 "Help" challenge binaries, this script finds all such calls and renames their output variables with the resulting plaintext.
//@author Andrew Barbarello
//@category Flare.2019

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FlareHelpDecryptAll extends GhidraScript {

	@Override
	protected void run() throws Exception {
		final Function calledFun = getFunctionAt(getInstructionContaining(currentAddress).getAddress(0));
		if (calledFun == null) {
			// Note that this could be an indirect call, but we don't care, we're only
			// looking for direct calls to RC4 decryption function
			println("Not at a direct call to function?");
			return;
		}

		ReferenceIterator iter = currentProgram.getReferenceManager().getReferencesTo(calledFun.getEntryPoint());
		while (iter.hasNext() && !monitor.isCancelled()) {
			Reference r = iter.next();
			if (r.getReferenceType().isCall()) {
				printf("Processing call at %s\n", r.getFromAddress());
				GhidraState clone = new GhidraState(state);
				clone.setCurrentAddress(r.getFromAddress());
				try {
					runScript("FlareHelpDecryptRC4Call.java", clone);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
}
