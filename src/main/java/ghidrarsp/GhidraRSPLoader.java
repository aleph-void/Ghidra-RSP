/* ###
* IP: GHIDRA
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package ghidrarsp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads a Nintendo 64 RSP microcode image (the contents of IMEM) as the RSP language.
 *
 * IMEM is mapped at 0x1000 (boot microcode, which runs from the start of IMEM) or 0x1080 (main
 * microcode, which the boot microcode DMAs to IMEM+0x80); DMEM, optionally loaded from a second file,
 * is at 0x0000-0x0FFF. The OSTask structure the CPU leaves at DMEM 0xFC0 is applied as a data type.
 */
public class GhidraRSPLoader extends AbstractProgramWrapperLoader {

    private static final String OPTION_IS_BOOT = "Is Boot";
    private static final String OPTION_DMEM = "DMEM file (optional)";
    private static final int DMEM_SIZE = 0x1000;
    private static final int IMEM_BASE = 0x1000;

    @Override
    public String getName() {
        return "Nintendo 64 RSP loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // IMEM is 4 KB of 32-bit instructions. There is no signature to look for, so the loader is
        // offered (not preferred) for any file of that shape: pick it explicitly.
        long len = provider.length();
        if (len > 0 && len <= DMEM_SIZE && len % 4 == 0) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("RSP:BE:32:default", "default"), false));
        }

        return loadSpecs;
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {

        ByteProvider provider = settings.provider();
        List<Option> options = settings.options();
        MessageLog log = settings.log();
        FlatProgramAPI api = new FlatProgramAPI(program);
        boolean isBoot = OptionUtils.getBooleanOptionValue(OPTION_IS_BOOT, options, false);
        String dmemPath = OptionUtils.getOption(OPTION_DMEM, options, "");
        int textBase = isBoot ? IMEM_BASE : IMEM_BASE + 0x80;

        byte[] imem = provider.readBytes(0, provider.length());
        if (textBase - IMEM_BASE + imem.length > DMEM_SIZE) {
            throw new IOException("the microcode does not fit in IMEM (4 KB)");
        }

        byte[] dmem = new byte[0];
        if (dmemPath != null && !dmemPath.isBlank()) {
            File f = new File(dmemPath.trim());
            if (!f.isFile()) {
                throw new IOException("DMEM file not found: " + f);
            }
            dmem = Files.readAllBytes(f.toPath());
            if (dmem.length > DMEM_SIZE) {
                throw new IOException("the DMEM file is larger than DMEM (4 KB)");
            }
        }

        try {
            if (dmem.length > 0) {
                MemoryBlock b = api.createMemoryBlock("dmem", api.toAddr(0), dmem, false);
                b.setPermissions(true, true, false);
            }
            if (dmem.length < DMEM_SIZE) {
                MemoryBlock b = program.getMemory().createUninitializedBlock("dmem.uninit",
                    api.toAddr(dmem.length), DMEM_SIZE - dmem.length, false);
                b.setPermissions(true, true, false);
            }
            MemoryBlock code = api.createMemoryBlock("imem", api.toAddr(textBase), imem, false);
            code.setPermissions(true, false, true);
            api.addEntryPoint(api.toAddr(textBase));
            api.createLabel(api.toAddr(textBase), isBoot ? "boot_ucode" : "main_ucode", true);
            api.createData(api.toAddr(0xFC0), new OSTask().toDataType());
            api.createLabel(api.toAddr(0xFC0), "OSTask", true);
        } catch (Exception e) {
            log.appendException(e);
            throw new IOException("could not create the RSP memory map: " + e.getMessage(), e);
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean mirrorFsLayout, boolean isLoadIntoProgram) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
            mirrorFsLayout, isLoadIntoProgram);

        list.add(new Option(OPTION_IS_BOOT, false, Boolean.class,
            Loader.COMMAND_LINE_ARG_PREFIX + "-isBoot"));
        list.add(new Option(OPTION_DMEM, "", String.class,
            Loader.COMMAND_LINE_ARG_PREFIX + "-dmemFile"));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program) {
        String dmemPath = OptionUtils.getOption(OPTION_DMEM, options, "");
        if (dmemPath != null && !dmemPath.isBlank() && !new File(dmemPath.trim()).isFile()) {
            return "DMEM file not found: " + dmemPath;
        }
        return super.validateOptions(provider, loadSpec, options, program);
    }
}
