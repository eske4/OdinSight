set(EBPF_PROGRAMS master.bpf.c print_test.bpf.c)
# src/eBPF_prog/CMakeLists.txt
set_source_files_properties(${EBPF_PROGRAMS} PROPERTIES LANGUAGE C)

# 1. Keep the library so the LSP/clangd works
add_library(ebpf_targets OBJECT ${EBPF_PROGRAMS})
target_include_directories(ebpf_targets PRIVATE ${EBPF_INTERNAL_INCLUDES})
target_link_libraries(ebpf_targets PRIVATE bpf_headers)
target_compile_options(
  ebpf_targets
  PRIVATE -target
          bpf
          -O2
          -g
          -x
          c
          -Wno-unused-parameter
          -Wno-missing-declarations
          -std=gnu17
          # This is the critical line for Kprobes:
          -D__TARGET_ARCH_x86)
          
# 1. Map skeletons to their specific object files
# 1. Map skeletons to their specific object files
set(ALL_SKEL_TARGETS "")

foreach(src ${EBPF_PROGRAMS})
    # Transform "master.bpf.c" -> "master"
    string(REGEX REPLACE "\\.bpf\\.c$" "" name ${src})
    
    set(SKEL_H "${SKEL_OUT_DIR}/${name}.skel.h")
    
    # CRITICAL: Use the actual object file location CMake uses for OBJECT libraries
    # This is much more reliable than guessing the 'CMakeFiles' path.
    set(OBJ_FILE "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ebpf_targets.dir/${src}.o")

    add_custom_command(
        OUTPUT "${SKEL_H}"
        COMMAND bpftool gen skeleton "${OBJ_FILE}" name "${name}" > "${SKEL_H}"
        # This tells CMake: "Wait for the ebpf_targets compilation to finish first"
        DEPENDS ebpf_targets "${OBJ_FILE}"
        VERBATIM
        COMMENT "--> Generating skeleton for: ${name}"
    )

    # Create a target for this specific header
    set(SKEL_TARGET "${name}_skel_gen")
    add_custom_target(${SKEL_TARGET} DEPENDS "${SKEL_H}")
    
    list(APPEND ALL_SKEL_TARGETS ${SKEL_TARGET})
endforeach()

# 2. Create the MASTER target that the rest of the project can see
add_custom_target(generate_ebpf_skeletons ALL DEPENDS ${ALL_SKEL_TARGETS})

