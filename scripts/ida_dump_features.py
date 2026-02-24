import ida_funcs
import ida_bytes
import ida_segment
import idaapi
import idautils
import idc
import os
import re
import traceback

idaapi.auto_wait()

filename = idaapi.get_root_filename()
path = os.getcwd()


def get_demangled_name(name):
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name


def extract_feature_name(demangled_name):
    match = re.search(r'wil::details::FeatureImpl<([^>]+)>::', demangled_name)
    if match:
        return match.group(1)
    return None


# wil dispatches some feature checks through cfg indirect calls via
# __guard_dispatch_icall_fptr. the feature id gets loaded into rcx right
# before the dispatch thunk, so we find that call and walk backwards to
# grab the immediate. 15 instructions is a pretty conservative scan window
def find_imm_internal(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    for head in idautils.Heads(func.start_ea, func.end_ea):
        flags = ida_bytes.get_flags(head)
        if not ida_bytes.is_code(flags):
            continue

        mnem = idc.print_insn_mnem(head)
        if mnem == "call":
            disasm = idc.generate_disasm_line(head, 0)
            if '__guard_dispatch_icall_fptr' in disasm or 'guard_dispatch_icall' in disasm:
                scan_addr = head
                for _ in range(15):
                    scan_addr = idc.prev_head(scan_addr, func.start_ea)
                    if scan_addr == idc.BADADDR or scan_addr < func.start_ea:
                        break

                    prev_mnem = idc.print_insn_mnem(scan_addr)
                    if prev_mnem == "mov":
                        op0_ty = idc.get_operand_type(scan_addr, 0)
                        op1_ty = idc.get_operand_type(scan_addr, 1)

                        if op0_ty == idc.o_reg and op1_ty == idc.o_imm:
                            reg_name = idc.print_operand(scan_addr, 0).lower()
                            imm_val = idc.get_operand_value(scan_addr, 1)

                            if reg_name in ['ecx', 'rcx']:
                                # feature ids are always >= 10000 afaict, anything
                                # smaller is probably unrelated. upper bound is u64 max
                                # because whatever.
                                if 10000 <= imm_val <= 18446744073709551615:
                                    return imm_val
    return None
    
####################################################################################
# this is a multi-strat feature id discovery. there's several strategies in order of
# reliability because no single approach works for all featureimpl instantiations:
#
#   strat 1: find direct calls to known wil api functions (ReportUsageToService,
#            GetFeatureEnabledState, etc.) and grab the id from argument registers
#            right before the call. I've found this to be the most reliable.
#
#   strat 2: fall back to the cfg indirect dispatch pattern (find_imm_internal),
#            which catches cases where the call goes through __guard_dispatch_icall.
#
#   strat 3: some featureimpl methods don't contain the id themselves -- they
#            delegate to GetCurrentFeatureEnabledState. follow that call recursively
#            (depth-limited to 2 to avoid runaway chains).
#
#   strat 4: brute-force collect all large immediates loaded into argument registers.
#            we prefer rdx over rcx because ReportUsageToService takes the id as
#            arg2 (rdx) and that path is more commonly what we're tracing through,
#            while GetFeatureEnabledState takes it as arg1 (rcx).
####################################################################################
def attempt_feature_id_discovery(func_ea, feature_name=None, depth=0):
    if depth > 2:
        return None

    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    wil_functions = ['ReportUsageToService', 'GetFeatureEnabledState', 'RecordFeatureUsage', 'SubscribeFeatureStateChangeNotification']

    for head in idautils.Heads(func.start_ea, func.end_ea):
        flags = ida_bytes.get_flags(head)
        if not ida_bytes.is_code(flags):
            continue

        mnem = idc.print_insn_mnem(head)
        if mnem == "call":
            op_ty = idc.get_operand_type(head, 0)
            if op_ty in [idc.o_near, idc.o_far, idc.o_mem]:
                target_ea = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target_ea)
                if target_name:
                    demangled_target = get_demangled_name(target_name)

                    is_wil_call = any(wf in demangled_target for wf in wil_functions)
                    if is_wil_call:
                        # wider scan window than find_imm_internal because
                        # direct wil calls often have more argument setup between
                        # the mov and the call site
                        scan_addr = head
                        for _ in range(32):
                            scan_addr = idc.prev_head(scan_addr, func.start_ea)
                            if scan_addr == idc.BADADDR or scan_addr < func.start_ea:
                                break

                            prev_mnem = idc.print_insn_mnem(scan_addr)
                            if prev_mnem == "mov":
                                op0_ty = idc.get_operand_type(scan_addr, 0)
                                op1_ty = idc.get_operand_type(scan_addr, 1)

                                if op0_ty == idc.o_reg and op1_ty == idc.o_imm:
                                    reg_name = idc.print_operand(scan_addr, 0).lower()
                                    imm_val = idc.get_operand_value(scan_addr, 1)
                                    
                                    if 10000 <= imm_val <= 0xFFFFFFFFFFFFFFFF:
                                        if reg_name in ['edx', 'rdx', 'ecx', 'rcx']:
                                            return imm_val

    result = find_imm_internal(func_ea)
    if result:
        return result

    for head in idautils.Heads(func.start_ea, func.end_ea):
        flags = ida_bytes.get_flags(head)
        if not ida_bytes.is_code(flags):
            continue

        mnem = idc.print_insn_mnem(head)
        if mnem == "call":
            op_ty = idc.get_operand_type(head, 0)
            if op_ty in [idc.o_near, idc.o_far, idc.o_mem]:
                target_ea = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target_ea)
                if target_name:
                    demangled_target = get_demangled_name(target_name)

                    if '>::GetCurrentFeatureEnabledState' in demangled_target:
                        if feature_name is None or feature_name in demangled_target:
                            result = attempt_feature_id_discovery(target_ea, feature_name, depth + 1)
                            if result:
                                return result

    feature_ids = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        flags = ida_bytes.get_flags(head)
        if not ida_bytes.is_code(flags):
            continue

        mnem = idc.print_insn_mnem(head)
        if mnem == "mov":
            op0_ty = idc.get_operand_type(head, 0)
            op1_ty = idc.get_operand_type(head, 1)

            if op0_ty == idc.o_reg and op1_ty == idc.o_imm:
                reg_name = idc.print_operand(head, 0).lower()
                imm_val = idc.get_operand_value(head, 1)

                if 10000 <= imm_val <= 0xFFFFFFFFFFFFFFFF:
                    if reg_name in ['edx', 'rdx', 'ecx', 'rcx']:
                        feature_ids.append((head, imm_val, reg_name))

    # rdx = arg2, used by ReportUsageToService
    for addr, val, reg in feature_ids:
        if reg in ['edx', 'rdx']:
            return val

    # rcx = arg1, used by GetFeatureEnabledState
    for addr, val, reg in feature_ids:
        if reg in ['ecx', 'rcx']:
            return val

    return None


def find_all_feature_impl_functions():
    results = []

    # ReportUsage is checked first because it's the most reliable source of feature ids (the id is always passed as arg2)
    target_methods = [
        '>::ReportUsage',
        '>::GetCurrentFeatureEnabledState',
        '>::GetCachedFeatureEnabledState',
    ]

    for addr, name in idautils.Names():
        if not ida_funcs.get_func(addr):
            continue

        demangled = get_demangled_name(name)

        if 'wil::details::FeatureImpl<' in demangled:
            for method in target_methods:
                if method in demangled:
                    feature_name = extract_feature_name(demangled)
                    if feature_name:
                        method_name = method.replace('>::', '')
                        results.append((addr, name, demangled, feature_name, method_name))
                    break

    return results


def extract_feature_id_from_packed(packed_qword):
    return packed_qword & 0xFFFFFFFF


# search for Feature_*__private_descriptor symbols in .rdata. each descriptor
# struct has 3 pointers (featureState, reporting, logged_traits) followed by a
# packed qword with the feature id in the low 32 bits. on 32-bit binaries the
# pointers are 4 bytes so the packed field sits at +0x0C instead of +0x18.
def find_rdata_feature_descriptors(report_file=None):
    features = {}
    is_64 = idaapi.inf_is_64bit()
    ptr_size = 8 if is_64 else 4
    packed_offset = ptr_size * 3

    for ea, name in idautils.Names():
        display_name = get_demangled_name(name)

        # try both demangled and raw mangled names because ida sometimes
        # only demangles one form depending on the compiler/linker
        for candidate in (display_name, name):
            match = re.match(r'^(Feature_[\w]+?)__private_descriptor$', candidate)
            if match:
                break
        else:
            continue

        feature_name = match.group(1)

        if is_64:
            packed_val = ida_bytes.get_qword(ea + packed_offset)
        else:
            packed_val = ida_bytes.get_dword(ea + packed_offset)

        if packed_val == 0 or packed_val == 0xFFFFFFFFFFFFFFFF:
            continue

        feature_id = extract_feature_id_from_packed(packed_val)

        if feature_id < 10000:
            continue

        addr_str = f"0x{ea:016X}" if is_64 else f"0x{ea:08X}"

        if feature_name not in features:
            features[feature_name] = feature_id
            if report_file:
                report_file.write(f"]] {feature_name}={feature_id}  (from .rdata descriptor @ {addr_str}, raw packed=0x{packed_val:X})\n")
                report_file.flush()

    return features


def main():
    output_file = os.path.join(path, "AnalysisResults.txt")

    with open(output_file, "w", encoding="utf-8") as out:
        out.write(f"wil feature-id results in {filename}\n")

        try:
            feature_funcs = find_all_feature_impl_functions()
            out.write(f"]] found {len(feature_funcs)} FeatureImpl functions\n")
            out.flush()

            features_found = {}

            for addr, mangled, demangled, feature_name, method_name in feature_funcs:
                addr_str = f"0x{addr:016X}" if idaapi.inf_is_64bit() else f"0x{addr:08X}"

                if feature_name in features_found and features_found[feature_name] != 0:
                    continue

                feature_id = attempt_feature_id_discovery(addr, feature_name)

                if feature_id:
                    features_found[feature_name] = feature_id
                else:
                    if feature_name not in features_found:
                        features_found[feature_name] = 0

                out.write(f"    source: {method_name} @ {addr_str}\n\n")
                out.flush()

            rdata_features = find_rdata_feature_descriptors(report_file=out)

            rdata_new = 0
            rdata_filled = 0
            for fname, fid in rdata_features.items():
                if fname not in features_found:
                    features_found[fname] = fid
                    rdata_new += 1
                elif features_found[fname] == 0 and fid != 0:
                    features_found[fname] = fid
                    rdata_filled += 1

            out.write(f"\n]]> .rdata scan: {len(rdata_features)} descriptors found, "
                    f"{rdata_new} new features, {rdata_filled} IDs filled\n")
            out.flush()

            out.write("[[FEATURE MAP]]\n")

            for feature_name in sorted(features_found.keys()):
                feature_id = features_found[feature_name]
                if feature_id == 0:
                    out.write(f"{feature_name}=00000000\n")
                else:
                    out.write(f"{feature_name}={feature_id}\n")

            out.write("\n")
            out.write(f"unique features: {len(features_found)}\n")
            out.write(f"binary: {filename}\n")

        except Exception as err:
            out.write(f"\n{err}\n")
            out.write(f"{traceback.format_exc()}\n")

    print(f"]]> analysis completed. results written to {output_file}")


if __name__ == "__main__":
    main()
    idaapi.qexit(0)
