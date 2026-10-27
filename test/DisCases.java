// Decode a list of 32-bit words (8 hex digits per line, big endian) with the program's language, word i
// placed at 0x1000 + 4*(i mod 1024), and print "<hex> <len> <text>" per case ("BAD" if the language rejects it).
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class DisCases extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		long idx = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(
					0x1000 + 4 * (idx++ & 0x3ff));
				byte[] b = new byte[line.length() / 2 + 8];
				for (int i = 0; i < line.length() / 2; i++) {
					b[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
				}
				ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
				String text;
				int n;
				try {
					MemBuffer buf = new ByteMemBufferImpl(a, b, true);
					InstructionPrototype proto = lang.parse(buf, ctx, false);
					PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
					text = pi.toString();
					n = pi.getLength();
				}
				catch (Exception e) {
					text = "BAD";
					n = 0;
				}
				out.printf("%s %d %s%n", line, n, text);
			}
		}
		out.close();
	}
}
