// P-code semantics check for the RSP module.  Reads test/emu/cases.txt (expectations worked out by hand
// from the RSP instruction semantics, not from the module's own output), and for each case writes the
// code at 0x1000, sets registers and memory, emulates with Ghidra's EmulatorHelper until the PC reaches
// the end of the code (or the address given by "until"), and compares registers and memory.
//
// Case format (one directive per line, '#' comments):
//   case <name> [broken]        "broken" cases carry a deliberately wrong expectation
//   code <hex words...>         instruction words placed at 0x1000 (big endian)
//   until <hex-address>         stop when PC reaches this address (default: end of code)
//   set <reg> <value>           register (any size; values are hex or decimal)
//   set mem:<hex-addr> <hex bytes>
//   expect <reg> <value> | expect mem:<hex-addr> <hex bytes> | expect PC <value>
//   end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class EmuTest extends GhidraScript {

	private static class Case {
		String name;
		boolean broken;
		byte[] code;
		long until = -1;
		List<String[]> set = new ArrayList<>();
		List<String[]> expect = new ArrayList<>();
	}

	private static byte[] hexBytes(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return b;
	}

	private static BigInteger num(String s) {
		return s.startsWith("0x") || s.startsWith("-0x") ? new BigInteger(
			s.replace("0x", ""), 16) : new BigInteger(s);
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						c.broken = f.length > 2 && f[2].equals("broken");
						break;
					case "code":
						String hex = String.join("", java.util.Arrays.copyOfRange(f, 1, f.length));
						c.code = hexBytes(hex);
						break;
					case "until":
						c.until = Long.parseLong(f[1], 16);
						break;
					case "set":
						c.set.add(new String[] { f[1], f[2] });
						break;
					case "expect":
						c.expect.add(new String[] { f[1], f[2] });
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private Address addr(long off) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
	}

	private String runCase(Case c) throws Exception {
		Address start = addr(0x1000);
		Address end = c.until >= 0 ? addr(c.until) : start.add(c.code.length);
		clearListing(new AddressSet(start, start.add(c.code.length)));
		setBytes(start, c.code);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (String[] e : c.set) {
				if (e[0].startsWith("mem:")) {
					emu.writeMemory(addr(Long.parseLong(e[0].substring(4), 16)), hexBytes(e[1]));
				}
				else {
					emu.writeRegister(e[0], num(e[1]));
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			int steps = 0;
			while (!emu.getExecutionAddress().equals(end)) {
				if (++steps > 200) {
					return "did not reach the end (pc " + emu.getExecutionAddress() + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + emu.getExecutionAddress() + ": " +
						emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (String[] e : c.expect) {
				if (e[0].startsWith("mem:")) {
					byte[] want = hexBytes(e[1]);
					byte[] got = emu.readMemory(addr(Long.parseLong(e[0].substring(4), 16)), want.length);
					for (int i = 0; i < want.length; i++) {
						if (want[i] != got[i]) {
							bad.append(String.format(" %s: byte %d is %02x (expected %02x);", e[0], i,
								got[i] & 0xff, want[i] & 0xff));
							break;
						}
					}
					continue;
				}
				BigInteger got;
				if (e[0].equals("PC")) {
					got = BigInteger.valueOf(emu.getExecutionAddress().getOffset());
				}
				else {
					got = emu.readRegister(e[0]);
				}
				BigInteger want = num(e[1]);
				if (!got.equals(want)) {
					bad.append(String.format(" %s=0x%s (expected 0x%s);", e[0], got.toString(16),
						want.toString(16)));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation: %d passed, %d failed, broken expectation %s%n", pass,
			fail + brokenMissed, brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
