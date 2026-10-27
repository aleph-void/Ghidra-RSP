// Runs single instructions from a case file in Ghidra's emulator and prints the resulting RSP state in the
// format of test/ares/harness.cpp (see there for the case format).  Script args: <cases.txt> <out.txt>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SemDiff extends GhidraScript {
	static final String[] GPR = new String[32];
	static {
		GPR[0] = "zero";
		for (int i = 1; i < 32; i++) {
			GPR[i] = i == 29 ? "sp" : i == 31 ? "ra" : "r" + i;
		}
	}
	static final int DMEM = 1280;

	private Address addr(long off) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
	}

	private static byte[] hexBytes(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return b;
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x", x & 0xff));
		}
		return sb.toString();
	}

	private static String pad(BigInteger v, int digits) {
		String s = v.toString(16);
		while (s.length() < digits) {
			s = "0" + s;
		}
		return s;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		List<String[]> chunk = new ArrayList<>();
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				if (line.isBlank()) {
					continue;
				}
				chunk.add(line.trim().split(" "));
				if (chunk.size() == 256) {
					runChunk(chunk, out);
					chunk.clear();
				}
			}
		}
		if (!chunk.isEmpty()) {
			runChunk(chunk, out);
		}
		out.close();
	}

	private void runChunk(List<String[]> cases, PrintStream out) throws Exception {
		// write all instruction words first (program memory), one per case
		for (int k = 0; k < cases.size(); k++) {
			long w = Long.parseLong(cases.get(k)[0], 16);
			setBytes(addr(0x1000 + 4 * k), new byte[] { (byte) (w >> 24), (byte) (w >> 16), (byte) (w >> 8), (byte) w });
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (int k = 0; k < cases.size(); k++) {
				String[] f = cases.get(k);
				int p = 1;
				for (int i = 0; i < 32; i++) {
					emu.writeRegister("v" + i, new BigInteger(f[p++], 16));
				}
				emu.writeRegister("ACC_H", new BigInteger(f[p++], 16));
				emu.writeRegister("ACC_M", new BigInteger(f[p++], 16));
				emu.writeRegister("ACC_L", new BigInteger(f[p++], 16));
				emu.writeRegister("VCO", new BigInteger(f[p++], 16));
				emu.writeRegister("VCC", new BigInteger(f[p++], 16));
				emu.writeRegister("VCE", new BigInteger(f[p++], 16));
				emu.writeRegister("DIVIN", new BigInteger(f[p++], 16));
				emu.writeRegister("DIVOUT", new BigInteger(f[p++], 16));
				emu.writeRegister("DIVDP", new BigInteger(f[p++], 16));
				for (int i = 0; i < 32; i++) {
					BigInteger v = new BigInteger(f[p++], 16);
					if (i != 0) {
						emu.writeRegister(GPR[i], v);
					}
				}
				emu.writeMemory(addr(0), hexBytes(f[p++]));
				emu.writeRegister(emu.getPCRegister(), 0x1000 + 4 * k);
				if (System.getenv("RSP_DEBUG") != null) {
					try {
						emu.getEmulator().executeInstruction(false, monitor);
					}
					catch (Throwable t) {
						t.printStackTrace(out);
					}
					continue;
				}
				if (!emu.step(monitor)) {
					out.println("ERROR " + emu.getLastError());
					continue;
				}
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < 32; i++) {
					sb.append(pad(emu.readRegister("v" + i), 32)).append(' ');
				}
				sb.append(pad(emu.readRegister("ACC_H"), 32)).append(' ');
				sb.append(pad(emu.readRegister("ACC_M"), 32)).append(' ');
				sb.append(pad(emu.readRegister("ACC_L"), 32)).append(' ');
				sb.append(pad(emu.readRegister("VCO"), 4)).append(' ');
				sb.append(pad(emu.readRegister("VCC"), 4)).append(' ');
				sb.append(pad(emu.readRegister("VCE"), 2)).append(' ');
				sb.append(pad(emu.readRegister("DIVIN"), 4)).append(' ');
				sb.append(pad(emu.readRegister("DIVOUT"), 4)).append(' ');
				sb.append(pad(emu.readRegister("DIVDP"), 1)).append(' ');
				for (int i = 0; i < 32; i++) {
					BigInteger v = i == 0 ? BigInteger.ZERO : emu.readRegister(GPR[i]);
					sb.append(pad(v, 8)).append(' ');
				}
				sb.append(hex(emu.readMemory(addr(0), DMEM)));
				out.println(sb);
			}
		}
		finally {
			emu.dispose();
		}
	}
}
