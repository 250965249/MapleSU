; ModuleID = 'D:/sdk-recon-work/sdk-rebuild\kit\m034\module_base_cpu_icache_sync.o'
source_filename = "C:/Users/abc/Desktop/testModule/kernel_module_kit/src/jni/../../../kernel_module_kit/src/jni/module_base_cpu_icache_sync.cpp"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-none-linux-android21"

%"class.std::__ndk1::vector" = type { ptr, ptr, %"class.std::__ndk1::__compressed_pair.2" }
%"class.std::__ndk1::__compressed_pair.2" = type { %"struct.std::__ndk1::__compressed_pair_elem.3" }
%"struct.std::__ndk1::__compressed_pair_elem.3" = type { ptr }
%struct.__sFILE = type { [152 x i8] }
%"class.std::__ndk1::basic_ostream" = type { ptr, %"class.std::__ndk1::basic_ios.base" }
%"class.std::__ndk1::basic_ios.base" = type <{ %"class.std::__ndk1::ios_base", ptr, i32 }>
%"class.std::__ndk1::ios_base" = type { ptr, i32, i64, i64, i32, i32, ptr, ptr, ptr, ptr, i64, i64, ptr, i64, i64, ptr, i64, i64 }
%"class.std::__ndk1::locale::id" = type <{ %"struct.std::__ndk1::once_flag", i32, [4 x i8] }>
%"struct.std::__ndk1::once_flag" = type { i64 }
%"struct.asmjit::v1_16::OperandSignature" = type { i32 }
%"struct.std::__ndk1::basic_string<char>::__long" = type { %struct.anon, i64, ptr }
%struct.anon = type { i64 }
%"struct.std::__ndk1::__exception_guard" = type <{ %"class.std::__ndk1::vector<std::__ndk1::string>::__destroy_vector", i8, [7 x i8] }>
%"class.std::__ndk1::vector<std::__ndk1::string>::__destroy_vector" = type { ptr }
%"class.std::__ndk1::basic_string" = type { %"class.std::__ndk1::__compressed_pair" }
%"class.std::__ndk1::__compressed_pair" = type { %"struct.std::__ndk1::__compressed_pair_elem" }
%"struct.std::__ndk1::__compressed_pair_elem" = type { %"struct.std::__ndk1::basic_string<char>::__rep" }
%"struct.std::__ndk1::basic_string<char>::__rep" = type { %union.anon }
%union.anon = type { %"struct.std::__ndk1::basic_string<char>::__long" }
%"class.asmjit::v1_16::Imm" = type { %"class.asmjit::v1_16::Operand" }
%"class.asmjit::v1_16::Operand" = type { %"struct.asmjit::v1_16::Operand_" }
%"struct.asmjit::v1_16::Operand_" = type { %"struct.asmjit::v1_16::OperandSignature", i32, [2 x i32] }
%"class.asmjit::v1_16::Environment" = type { i8, i8, i8, i8, i8, i8, i8, i8 }
%"class.std::__ndk1::unique_ptr.17" = type { %"class.std::__ndk1::__compressed_pair.18" }
%"class.std::__ndk1::__compressed_pair.18" = type { %"struct.std::__ndk1::__compressed_pair_elem.19" }
%"struct.std::__ndk1::__compressed_pair_elem.19" = type { ptr }
%"class.std::__ndk1::unique_ptr" = type { %"class.std::__ndk1::__compressed_pair.12" }
%"class.std::__ndk1::__compressed_pair.12" = type { %"struct.std::__ndk1::__compressed_pair_elem.13" }
%"struct.std::__ndk1::__compressed_pair_elem.13" = type { ptr }
%"class.std::__ndk1::unique_ptr.33" = type { %"class.std::__ndk1::__compressed_pair.34" }
%"class.std::__ndk1::__compressed_pair.34" = type { %"struct.std::__ndk1::__compressed_pair_elem.35" }
%"struct.std::__ndk1::__compressed_pair_elem.35" = type { ptr }
%"struct.(anonymous namespace)::aarch64_asm_ctx" = type { %"class.std::__ndk1::unique_ptr", %"class.std::__ndk1::unique_ptr.17", %"class.std::__ndk1::unique_ptr.27", %"class.std::__ndk1::unique_ptr.33" }
%"class.std::__ndk1::unique_ptr.27" = type { %"class.std::__ndk1::__compressed_pair.28" }
%"class.std::__ndk1::__compressed_pair.28" = type { %"struct.std::__ndk1::__compressed_pair_elem.29" }
%"struct.std::__ndk1::__compressed_pair_elem.29" = type { ptr }
%"class.asmjit::v1_16::Label" = type { %"class.asmjit::v1_16::Operand" }
%"class.std::__ndk1::vector.41" = type { ptr, ptr, %"class.std::__ndk1::__compressed_pair.42" }
%"class.std::__ndk1::__compressed_pair.42" = type { %"struct.std::__ndk1::__compressed_pair_elem.43" }
%"struct.std::__ndk1::__compressed_pair_elem.43" = type { ptr }
%"class.(anonymous namespace)::MyAsmJitErrorHandler" = type <{ %"class.asmjit::v1_16::ErrorHandler", i8, [7 x i8] }>
%"class.asmjit::v1_16::ErrorHandler" = type { ptr }
%"class.asmjit::v1_16::BaseEmitter" = type { ptr, i8, i8, i8, i8, i32, i32, i64, i32, i32, i32, ptr, ptr, ptr, %"class.asmjit::v1_16::Environment", %"struct.asmjit::v1_16::OperandSignature", i32, %"struct.asmjit::v1_16::RegOnly", ptr, %"struct.asmjit::v1_16::BaseEmitter::Funcs" }
%"struct.asmjit::v1_16::RegOnly" = type { %"struct.asmjit::v1_16::OperandSignature", i32 }
%"struct.asmjit::v1_16::BaseEmitter::Funcs" = type { ptr, ptr, ptr, ptr, ptr }
%"class.asmjit::v1_16::CodeHolder" = type { %"class.asmjit::v1_16::Environment", %"class.asmjit::v1_16::CpuFeatures", i64, ptr, ptr, %"class.asmjit::v1_16::Zone", %"class.asmjit::v1_16::ZoneAllocator", %"class.asmjit::v1_16::ZoneVector", %"class.asmjit::v1_16::ZoneVector.21", %"class.asmjit::v1_16::ZoneVector.21", %"class.asmjit::v1_16::ZoneVector.22", %"class.asmjit::v1_16::ZoneVector.23", %"class.asmjit::v1_16::ZoneHash", i64, ptr, %"class.asmjit::v1_16::ZoneTree" }
%"class.asmjit::v1_16::CpuFeatures" = type { %"struct.asmjit::v1_16::CpuFeatures::Data" }
%"struct.asmjit::v1_16::CpuFeatures::Data" = type { %"struct.asmjit::v1_16::Support::Array.20" }
%"struct.asmjit::v1_16::Support::Array.20" = type { [4 x i64] }
%"class.asmjit::v1_16::Zone" = type { ptr, ptr, ptr, i8, i8, i8, i8, i32, i64 }
%"class.asmjit::v1_16::ZoneAllocator" = type { ptr, [10 x ptr], ptr }
%"class.asmjit::v1_16::ZoneVector" = type { %"class.asmjit::v1_16::ZoneVectorBase" }
%"class.asmjit::v1_16::ZoneVectorBase" = type { ptr, i32, i32 }
%"class.asmjit::v1_16::ZoneVector.21" = type { %"class.asmjit::v1_16::ZoneVectorBase" }
%"class.asmjit::v1_16::ZoneVector.22" = type { %"class.asmjit::v1_16::ZoneVectorBase" }
%"class.asmjit::v1_16::ZoneVector.23" = type { %"class.asmjit::v1_16::ZoneVectorBase" }
%"class.asmjit::v1_16::ZoneHash" = type { %"class.asmjit::v1_16::ZoneHashBase" }
%"class.asmjit::v1_16::ZoneHashBase" = type { ptr, i64, i32, i32, i32, i8, i8, [1 x ptr] }
%"class.asmjit::v1_16::ZoneTree" = type { ptr }
%"class.asmjit::v1_16::Section" = type { i32, i32, i32, i32, i64, i64, %"union.asmjit::v1_16::FixedString", %"struct.asmjit::v1_16::CodeBuffer" }
%"union.asmjit::v1_16::FixedString" = type { [9 x i32] }
%"struct.asmjit::v1_16::CodeBuffer" = type { ptr, i64, i64, i32 }
%struct.cpu_set_t = type { [16 x i64] }
%"struct.std::__ndk1::basic_string<char>::__short" = type { %struct.anon.0, [0 x i8], [23 x i8] }
%struct.anon.0 = type { i8 }
%"struct.std::__ndk1::__exception_guard.10" = type <{ %"class.std::__ndk1::_AllocatorDestroyRangeReverse", i8, [7 x i8] }>
%"class.std::__ndk1::_AllocatorDestroyRangeReverse" = type { ptr, ptr, ptr }
%"class.std::__ndk1::vector<unsigned char>::__destroy_vector" = type { ptr }
%"class.std::__ndk1::basic_ostream<char>::sentry" = type { i8, ptr }
%"class.std::__ndk1::basic_ios" = type <{ %"class.std::__ndk1::ios_base", ptr, i32, [4 x i8] }>
%"class.std::__ndk1::locale" = type { ptr }
%"struct.std::__ndk1::__exception_guard.49" = type <{ %"class.std::__ndk1::vector<unsigned char>::__destroy_vector", i8, [7 x i8] }>

$_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEC2B7v170000ESt16initializer_listIS6_E = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2B7v170000Ev = comdat any

$_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB7v170000Ev = comdat any

$_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m = comdat any

$_ZNSt6__ndk120__throw_length_errorB7v170000EPKc = comdat any

$_ZNSt12length_errorC2B7v170000EPKc = comdat any

$_ZSt28__throw_bad_array_new_lengthB7v170000v = comdat any

$__clang_call_terminate = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE11__vallocateB7v170000Em = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE18__construct_at_endIPKS6_Li0EEEvT_SC_m = comdat any

$_ZNSt6__ndk117__exception_guardINS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEED2B7v170000Ev = comdat any

$_ZNKSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE20__throw_length_errorB7v170000Ev = comdat any

$_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERSA_m = comdat any

$_ZNSt6__ndk19allocatorINS_12basic_stringIcNS_11char_traitsIcEENS0_IcEEEEE8allocateB7v170000Em = comdat any

$_ZNSt6__ndk130__uninitialized_allocator_copyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPKS6_S9_PS6_EET2_RT_T0_T1_SB_ = comdat any

$_ZNSt6__ndk117__exception_guardINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEED2B7v170000Ev = comdat any

$_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE25__init_copy_ctor_externalEPKcm = comdat any

$_ZNKSt6__ndk129_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPS6_EclB7v170000Ev = comdat any

$_ZNSt6__ndk119__allocator_destroyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEENS_16reverse_iteratorIPS6_EESA_EEvRT_T0_T1_ = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE16__destroy_vectorclB7v170000Ev = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE7__clearB7v170000Ev = comdat any

$_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE22__base_destruct_at_endB7v170000EPS6_ = comdat any

$_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm = comdat any

$_ZNSt6__ndk16vectorIhNS_9allocatorIhEEED2B7v170000Ev = comdat any

$_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1610CodeHolderEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_ = comdat any

$_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEED2B7v170000Ev = comdat any

$_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1612StringLoggerEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_ = comdat any

$_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1612StringLoggerENS_14default_deleteIS3_EEED2B7v170000Ev = comdat any

$_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_163a649AssemblerEJPNS2_10CodeHolderEEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_ = comdat any

$_ZNSt6__ndk110unique_ptrIN6asmjit5v1_163a649AssemblerENS_14default_deleteIS4_EEED2B7v170000Ev = comdat any

$_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEE5resetB7v170000EPS3_ = comdat any

$_ZNKSt6__ndk114default_deleteIN6asmjit5v1_1610CodeHolderEEclB7v170000EPS3_ = comdat any

$_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc = comdat any

$_ZNSt6__ndk14endlB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_ = comdat any

$_ZNSt6__ndk124__put_character_sequenceB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m = comdat any

$_ZNSt6__ndk116__pad_and_outputB7v170000IcNS_11char_traitsIcEEEENS_19ostreambuf_iteratorIT_T0_EES6_PKS4_S8_S8_RNS_8ios_baseES4_ = comdat any

$_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE4fillB7v170000Ev = comdat any

$_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE5widenB7v170000Ec = comdat any

$_ZNSt6__ndk19use_facetB7v170000INS_5ctypeIcEEEERKT_RKNS_6localeE = comdat any

$_ZNSt6__ndk18ios_base8setstateB7v170000Ej = comdat any

$_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE2icERKNS0_3ImmERKNS1_2GpE = comdat any

$_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3dsbERKNS0_3ImmE = comdat any

$_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3isbERKNS0_3ImmE = comdat any

$_ZNSt6__ndk16vectorIhNS_9allocatorIhEEEC2IPKhLi0EEET_S7_ = comdat any

$_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE11__vallocateB7v170000Em = comdat any

$_ZNSt6__ndk117__exception_guardINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED2B7v170000Ev = comdat any

$_ZNKSt6__ndk16vectorIhNS_9allocatorIhEEE20__throw_length_errorB7v170000Ev = comdat any

$_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIhEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m = comdat any

$_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE16__destroy_vectorclB7v170000Ev = comdat any

$skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53 = comdat any

$skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = comdat any

$_ZTSSt12length_error = comdat any

$_ZTSSt11logic_error = comdat any

$_ZTSSt9exception = comdat any

$_ZTISt9exception = comdat any

$_ZTISt11logic_error = comdat any

$_ZTISt12length_error = comdat any

$_ZTSSt20bad_array_new_length = comdat any

$_ZTSSt9bad_alloc = comdat any

$_ZTISt9bad_alloc = comdat any

$_ZTISt20bad_array_new_length = comdat any

@_ZN13kernel_module13export_symbolL27copy_from_user_symbol_namesE = internal global %"class.std::__ndk1::vector" zeroinitializer, align 8
@.str = private unnamed_addr constant [22 x i8] c"__arch_copy_from_user\00", align 1
@.str.1 = private unnamed_addr constant [17 x i8] c"__copy_from_user\00", align 1
@.str.2 = private unnamed_addr constant [16 x i8] c"_copy_from_user\00", align 1
@.str.3 = private unnamed_addr constant [21 x i8] c"arm64_copy_from_user\00", align 1
@.str.4 = private unnamed_addr constant [15 x i8] c"copy_from_user\00", align 1
@__dso_handle = external hidden global i8
@_ZN13kernel_module13export_symbolL25copy_to_user_symbol_namesE = internal global %"class.std::__ndk1::vector" zeroinitializer, align 8
@.str.6 = private unnamed_addr constant [20 x i8] c"__arch_copy_to_user\00", align 1
@.str.7 = private unnamed_addr constant [15 x i8] c"__copy_to_user\00", align 1
@.str.8 = private unnamed_addr constant [14 x i8] c"_copy_to_user\00", align 1
@.str.9 = private unnamed_addr constant [19 x i8] c"arm64_copy_to_user\00", align 1
@.str.10 = private unnamed_addr constant [13 x i8] c"copy_to_user\00", align 1
@_ZN13kernel_module13export_symbolL37copy_from_kernel_nofault_symbol_namesE = internal global %"class.std::__ndk1::vector" zeroinitializer, align 8
@.str.12 = private unnamed_addr constant [25 x i8] c"copy_from_kernel_nofault\00", align 1
@.str.13 = private unnamed_addr constant [18 x i8] c"probe_kernel_read\00", align 1
@.str.14 = private unnamed_addr constant [20 x i8] c"__probe_kernel_read\00", align 1
@skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53 = linkonce_odr hidden global [1024 x i8] zeroinitializer, comdat, align 1
@skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = linkonce_odr hidden local_unnamed_addr global ptr null, comdat, align 8
@__sF = external global [0 x %struct.__sFILE], align 8
@.str.16 = private unnamed_addr constant [38 x i8] c"child_logic: sched_getcpu failed: %s\0A\00", align 1
@.str.17 = private unnamed_addr constant [46 x i8] c"[icache] set_thread_cpu(%d) failed, skipping\0A\00", align 1
@.str.18 = private unnamed_addr constant [13 x i8] c"basic_string\00", align 1
@_ZTVN10__cxxabiv120__si_class_type_infoE = external global ptr
@_ZTSSt12length_error = linkonce_odr constant [17 x i8] c"St12length_error\00", comdat, align 1
@_ZTSSt11logic_error = linkonce_odr constant [16 x i8] c"St11logic_error\00", comdat, align 1
@_ZTVN10__cxxabiv117__class_type_infoE = external global ptr
@_ZTSSt9exception = linkonce_odr constant [13 x i8] c"St9exception\00", comdat, align 1
@_ZTISt9exception = linkonce_odr constant { ptr, ptr } { ptr getelementptr inbounds (ptr, ptr @_ZTVN10__cxxabiv117__class_type_infoE, i64 2), ptr @_ZTSSt9exception }, comdat, align 8
@_ZTISt11logic_error = linkonce_odr constant { ptr, ptr, ptr } { ptr getelementptr inbounds (ptr, ptr @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2), ptr @_ZTSSt11logic_error, ptr @_ZTISt9exception }, comdat, align 8
@_ZTISt12length_error = linkonce_odr constant { ptr, ptr, ptr } { ptr getelementptr inbounds (ptr, ptr @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2), ptr @_ZTSSt12length_error, ptr @_ZTISt11logic_error }, comdat, align 8
@_ZTVSt12length_error = available_externally unnamed_addr constant { [5 x ptr] } { [5 x ptr] [ptr null, ptr null, ptr @_ZNSt12length_errorD1Ev, ptr @_ZNSt12length_errorD0Ev, ptr @_ZNKSt11logic_error4whatEv] }, align 8
@_ZTSSt20bad_array_new_length = linkonce_odr constant [25 x i8] c"St20bad_array_new_length\00", comdat, align 1
@_ZTSSt9bad_alloc = linkonce_odr constant [13 x i8] c"St9bad_alloc\00", comdat, align 1
@_ZTISt9bad_alloc = linkonce_odr constant { ptr, ptr, ptr } { ptr getelementptr inbounds (ptr, ptr @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2), ptr @_ZTSSt9bad_alloc, ptr @_ZTISt9exception }, comdat, align 8
@_ZTISt20bad_array_new_length = linkonce_odr constant { ptr, ptr, ptr } { ptr getelementptr inbounds (ptr, ptr @_ZTVN10__cxxabiv120__si_class_type_infoE, i64 2), ptr @_ZTSSt20bad_array_new_length, ptr @_ZTISt9bad_alloc }, comdat, align 8
@.str.19 = private unnamed_addr constant [7 x i8] c"vector\00", align 1
@.str.20 = private unnamed_addr constant [35 x i8] c"set_thread_cpu: invalid cpu_id=%d\0A\00", align 1
@.str.21 = private unnamed_addr constant [50 x i8] c"set_thread_cpu: sched_setaffinity(%d) failed: %s\0A\00", align 1
@_ZTVN12_GLOBAL__N_120MyAsmJitErrorHandlerE = internal unnamed_addr constant { [5 x ptr] } { [5 x ptr] [ptr null, ptr null, ptr @_ZN6asmjit5v1_1612ErrorHandlerD2Ev, ptr @_ZN12_GLOBAL__N_120MyAsmJitErrorHandlerD0Ev, ptr @_ZN12_GLOBAL__N_120MyAsmJitErrorHandler11handleErrorEjPKcPN6asmjit5v1_1611BaseEmitterE] }, align 8, !type !0, !type !2, !type !4, !type !5
@_ZNSt6__ndk14cerrE = external global %"class.std::__ndk1::basic_ostream", align 8
@.str.22 = private unnamed_addr constant [16 x i8] c"[\E5\8F\91\E7\94\9F\E9\94\99\E8\AF\AF] \00", align 1
@.str.23 = private unnamed_addr constant [3 x i8] c": \00", align 1
@_ZNSt6__ndk15ctypeIcE2idE = external global %"class.std::__ndk1::locale::id", align 8
@_ZN6asmjit5v1_163a644regsL3xzrE = internal constant { %"struct.asmjit::v1_16::OperandSignature", i32, [2 x i32] } { %"struct.asmjit::v1_16::OperandSignature" { i32 134217785 }, i32 63, [2 x i32] zeroinitializer }, align 4
@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 65535, ptr @_GLOBAL__sub_I_module_base_cpu_icache_sync.cpp, ptr null }]
@llvm.compiler.used = appending global [3 x ptr] [ptr @__skroot_module_before_server_exit_action_81a98535f12c96a0b3e457727705e44c, ptr @__skroot_module_last_web_ui_server_port_db2a2bebe2b190482ad0ac73996c7b86, ptr @__skroot_module_web_ui_main_ceb6f0bbebe5c8978eb2168799aa0ca4], section "llvm.metadata"

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #0

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1) unnamed_addr #1 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = icmp ne ptr %1, null
  tail call void @llvm.assume(i1 %3)
  %4 = tail call i64 @strlen(ptr noundef nonnull dereferenceable(1) %1) #24
  tail call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef nonnull %1, i64 noundef %4) #25
  ret void
}

declare i32 @__gxx_personality_v0(...)

; Function Attrs: inlinehint minsize nounwind optsize uwtable
define available_externally void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) unnamed_addr #2 align 2 personality ptr @__gxx_personality_v0 {
  %2 = load i8, ptr %0, align 8
  %3 = and i8 %2, 1
  %4 = icmp eq i8 %3, 0
  br i1 %4, label %8, label %5

5:                                                ; preds = %1
  %6 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 2
  %7 = load ptr, ptr %6, align 8, !tbaa !12
  tail call void @_ZdlPv(ptr noundef %7) #26
  br label %8

8:                                                ; preds = %5, %1
  ret void
}

; Function Attrs: inlinehint minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEC2B7v170000ESt16initializer_listIS6_E(ptr noundef nonnull align 8 dereferenceable(24) %0, [2 x i64] %1) unnamed_addr #3 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = alloca %"struct.std::__ndk1::__exception_guard", align 8
  %4 = extractvalue [2 x i64] %1, 0
  %5 = inttoptr i64 %4 to ptr
  %6 = extractvalue [2 x i64] %1, 1
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(24) %0, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %3) #27
  store ptr %0, ptr %3, align 8, !tbaa.struct !15, !alias.scope !18
  %7 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard", ptr %3, i64 0, i32 1
  store i8 0, ptr %7, align 8, !tbaa !21, !alias.scope !18
  %8 = icmp eq i64 %6, 0
  br i1 %8, label %14, label %9

9:                                                ; preds = %2
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE11__vallocateB7v170000Em(ptr noundef nonnull align 8 dereferenceable(24) %0, i64 noundef %6) #25
          to label %10 unwind label %12

10:                                               ; preds = %9
  %11 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %5, i64 %6
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE18__construct_at_endIPKS6_Li0EEEvT_SC_m(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %5, ptr noundef nonnull %11, i64 noundef %6) #25
          to label %14 unwind label %12

12:                                               ; preds = %10, %9
  %13 = landingpad { ptr, i32 }
          cleanup
  call void @_ZNSt6__ndk117__exception_guardINS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %3) #24
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %3) #27
  resume { ptr, i32 } %13

14:                                               ; preds = %10, %2
  store i8 1, ptr %7, align 8, !tbaa !21
  call void @_ZNSt6__ndk117__exception_guardINS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %3) #24
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %3) #27
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #0

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) unnamed_addr #4 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = alloca %"class.std::__ndk1::vector<std::__ndk1::string>::__destroy_vector", align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2) #27
  store ptr %0, ptr %2, align 8, !tbaa !16
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %2) #25
          to label %3 unwind label %4

3:                                                ; preds = %1
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %2) #27
  ret void

4:                                                ; preds = %1
  %5 = landingpad { ptr, i32 }
          catch ptr null
  %6 = extractvalue { ptr, i32 } %5, 0
  call void @__clang_call_terminate(ptr %6) #28
  unreachable
}

; Function Attrs: nofree nounwind
declare i32 @__cxa_atexit(ptr, ptr, ptr) local_unnamed_addr #5

; Function Attrs: minsize mustprogress optsize uwtable
define weak void @__skroot_module_web_ui_main_ceb6f0bbebe5c8978eb2168799aa0ca4(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, i32 noundef %4, ptr noundef nonnull align 8 dereferenceable(8) %5) #6 {
  %7 = tail call i64 @__strlen_chk(ptr noundef nonnull @skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53, i64 noundef 1024) #25
  %8 = load ptr, ptr @skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5, align 8, !tbaa !16
  %9 = tail call i64 @unsafe_module_start_web_ui_server(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, ptr noundef %8, i32 noundef %4) #25
  store i64 %9, ptr %5, align 8, !tbaa !25
  ret void
}

; Function Attrs: minsize nofree nounwind optsize
declare noundef i32 @printf(ptr nocapture noundef readonly, ...) local_unnamed_addr #7

; Function Attrs: minsize optsize
declare i64 @unsafe_module_start_web_ui_server(ptr noundef, ptr noundef, ptr noundef, ptr noundef, ptr noundef, i32 noundef) local_unnamed_addr #8

; Function Attrs: minsize mustprogress optsize uwtable
define weak void @__skroot_module_last_web_ui_server_port_db2a2bebe2b190482ad0ac73996c7b86(ptr noundef nonnull align 4 dereferenceable(4) %0, ptr noundef nonnull align 8 dereferenceable(8) %1) #6 {
  %3 = tail call i64 @__strlen_chk(ptr noundef nonnull @skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53, i64 noundef 1024) #25
  %4 = tail call i64 @unsafe_module_get_last_web_ui_server_port(ptr noundef nonnull align 4 dereferenceable(4) %0) #25
  store i64 %4, ptr %1, align 8, !tbaa !25
  ret void
}

; Function Attrs: minsize optsize
declare i64 @unsafe_module_get_last_web_ui_server_port(ptr noundef nonnull align 4 dereferenceable(4)) local_unnamed_addr #8

; Function Attrs: minsize mustprogress optsize uwtable
define weak void @__skroot_module_before_server_exit_action_81a98535f12c96a0b3e457727705e44c(ptr noundef nonnull align 4 dereferenceable(4) %0, ptr noundef nonnull align 8 dereferenceable(8) %1) #6 {
  %3 = tail call i64 @__strlen_chk(ptr noundef nonnull @skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53, i64 noundef 1024) #25
  %4 = tail call i64 @unsafe_module_get_before_server_exit_action(ptr noundef nonnull align 4 dereferenceable(4) %0) #25
  store i64 %4, ptr %1, align 8, !tbaa !25
  ret void
}

; Function Attrs: minsize optsize
declare i64 @unsafe_module_get_before_server_exit_action(ptr noundef nonnull align 4 dereferenceable(4)) local_unnamed_addr #8

; Function Attrs: minsize optsize uwtable
define hidden noundef i64 @maple_icache_execute_once() local_unnamed_addr #1 personality ptr @__gxx_personality_v0 {
  %v1 = alloca %"class.asmjit::v1_16::Imm", align 4
  %v2 = alloca %"class.asmjit::v1_16::Imm", align 4
  %v3 = alloca %"class.asmjit::v1_16::Imm", align 4
  %v4 = alloca %"class.asmjit::v1_16::Environment", align 4
  %v5 = alloca %"class.std::__ndk1::unique_ptr.17", align 8
  %v6 = alloca %"class.std::__ndk1::unique_ptr", align 8
  %v7 = alloca %"class.std::__ndk1::unique_ptr.33", align 8
  %v8 = alloca ptr, align 8
  %v9 = alloca %"struct.(anonymous namespace)::aarch64_asm_ctx", align 8
  %v10 = alloca %"class.asmjit::v1_16::Label", align 4
  %v11 = alloca %"class.std::__ndk1::vector.41", align 8
  %v12 = alloca i64, align 8
  br label %v20

v20:
  %v23 = getelementptr inbounds %"class.asmjit::v1_16::Environment", ptr %v4, i64 0, i32 1
  %v24 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %v9, i64 0, i32 1
  %v25 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %v9, i64 0, i32 2
  %v26 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %v9, i64 0, i32 3
  %v27 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v3, i64 0, i32 1
  %v28 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v3, i64 0, i32 2
  %v29 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v3, i64 0, i32 2, i64 1
  %v30 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v2, i64 0, i32 1
  %v31 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v2, i64 0, i32 2
  %v32 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v2, i64 0, i32 2, i64 1
  %v33 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v1, i64 0, i32 1
  %v34 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v1, i64 0, i32 2
  %v35 = getelementptr inbounds %"struct.asmjit::v1_16::Operand_", ptr %v1, i64 0, i32 2, i64 1
  br label %v44

v44:
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %v9) #27
  call void @llvm.experimental.noalias.scope.decl(metadata !29)
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(32) %v9, i8 0, i64 32, i1 false), !alias.scope !29
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v4) #27, !noalias !29
  store i8 6, ptr %v4, align 4, !tbaa !32, !noalias !29
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 1 dereferenceable(7) %v23, i8 0, i64 7, i1 false), !noalias !29
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v5) #27, !noalias !29
  invoke void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1610CodeHolderEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr nonnull sret(%"class.std::__ndk1::unique_ptr.17") align 8 %v5) #25
          to label %v45 unwind label %v91, !noalias !29

v45:
  %v46 = load ptr, ptr %v5, align 8, !tbaa !16, !noalias !29
  store ptr null, ptr %v5, align 8, !tbaa !16, !noalias !29
  call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEE5resetB7v170000EPS3_(ptr noundef nonnull align 8 dereferenceable(8) %v24, ptr noundef %v46) #24
  call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %v5) #24
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v5) #27, !noalias !29
  %v47 = load ptr, ptr %v24, align 8, !tbaa !16, !alias.scope !29
  %v48 = call noundef i32 @_ZN6asmjit5v1_1610CodeHolder4initERKNS0_11EnvironmentEm(ptr noundef nonnull align 8 dereferenceable(344) %v47, ptr noundef nonnull align 1 dereferenceable(8) %v4, i64 noundef -1) #24
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v6) #27, !noalias !29
  invoke void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1612StringLoggerEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr nonnull sret(%"class.std::__ndk1::unique_ptr") align 8 %v6) #25
          to label %v49 unwind label %v93

v49:
  %v50 = load ptr, ptr %v6, align 8, !tbaa !16, !noalias !29
  store ptr null, ptr %v6, align 8, !tbaa !16, !noalias !29
  %v51 = load ptr, ptr %v9, align 8, !tbaa !16, !alias.scope !29
  store ptr %v50, ptr %v9, align 8, !tbaa !16, !alias.scope !29
  %v52 = icmp eq ptr %v51, null
  br i1 %v52, label %v63, label %v53

v53:
  %v54 = load ptr, ptr %v51, align 8, !tbaa !41
  %v55 = getelementptr inbounds ptr, ptr %v54, i64 1
  %v56 = load ptr, ptr %v55, align 8
  call void %v56(ptr noundef nonnull align 8 dereferenceable(56) %v51) #24
  %v57 = load ptr, ptr %v6, align 8, !tbaa !16, !noalias !29
  store ptr null, ptr %v6, align 8, !tbaa !16, !noalias !29
  %v58 = icmp eq ptr %v57, null
  br i1 %v58, label %v63, label %v59

v59:
  %v60 = load ptr, ptr %v57, align 8, !tbaa !41
  %v61 = getelementptr inbounds ptr, ptr %v60, i64 1
  %v62 = load ptr, ptr %v61, align 8
  call void %v62(ptr noundef nonnull align 8 dereferenceable(56) %v57) #24
  br label %v63

v63:
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v6) #27, !noalias !29
  %v64 = load ptr, ptr %v9, align 8, !tbaa !16, !alias.scope !29
  %v65 = load ptr, ptr %v24, align 8, !tbaa !16, !alias.scope !29
  call void @_ZN6asmjit5v1_1610CodeHolder9setLoggerEPNS0_6LoggerE(ptr noundef nonnull align 8 dereferenceable(344) %v65, ptr noundef %v64) #24
  %v66 = invoke noalias noundef nonnull dereferenceable(16) ptr @_Znwm(i64 noundef 16) #30
          to label %v67 unwind label %v95

v67:
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(16) %v66, i8 0, i64 16, i1 false), !noalias !43
  call void @_ZN6asmjit5v1_1612ErrorHandlerC2Ev(ptr noundef nonnull align 8 dereferenceable(8) %v66) #24, !noalias !43
  store ptr getelementptr inbounds ({ [5 x ptr] }, ptr @_ZTVN12_GLOBAL__N_120MyAsmJitErrorHandlerE, i64 0, inrange i32 0, i64 2), ptr %v66, align 8, !tbaa !41, !noalias !43
  %v68 = getelementptr inbounds %"class.(anonymous namespace)::MyAsmJitErrorHandler", ptr %v66, i64 0, i32 1
  store i8 0, ptr %v68, align 8, !tbaa !46, !noalias !43
  %v69 = load ptr, ptr %v25, align 8, !tbaa !16, !alias.scope !29
  store ptr %v66, ptr %v25, align 8, !tbaa !16, !alias.scope !29
  %v70 = icmp eq ptr %v69, null
  br i1 %v70, label %v75, label %v71

v71:
  %v72 = load ptr, ptr %v69, align 8, !tbaa !41
  %v73 = getelementptr inbounds ptr, ptr %v72, i64 1
  %v74 = load ptr, ptr %v73, align 8
  call void %v74(ptr noundef nonnull align 8 dereferenceable(9) %v69) #24
  br label %v75

v75:
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v7) #27, !noalias !29
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v8) #27, !noalias !29
  %v76 = load ptr, ptr %v24, align 8, !tbaa !16, !alias.scope !29
  store ptr %v76, ptr %v8, align 8, !tbaa !16, !noalias !29
  invoke void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_163a649AssemblerEJPNS2_10CodeHolderEEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr nonnull sret(%"class.std::__ndk1::unique_ptr.33") align 8 %v7, ptr noundef nonnull align 8 dereferenceable(8) %v8) #25
          to label %v77 unwind label %v97

v77:
  %v78 = load ptr, ptr %v7, align 8, !tbaa !16, !noalias !29
  store ptr null, ptr %v7, align 8, !tbaa !16, !noalias !29
  %v79 = load ptr, ptr %v26, align 8, !tbaa !16, !alias.scope !29
  store ptr %v78, ptr %v26, align 8, !tbaa !16, !alias.scope !29
  %v80 = icmp eq ptr %v79, null
  br i1 %v80, label %v103, label %v81

v81:
  %v82 = load ptr, ptr %v79, align 8, !tbaa !41
  %v83 = getelementptr inbounds ptr, ptr %v82, i64 1
  %v84 = load ptr, ptr %v83, align 8
  call void %v84(ptr noundef nonnull align 8 dereferenceable(176) %v79) #24
  %v85 = load ptr, ptr %v7, align 8, !tbaa !16, !noalias !29
  store ptr null, ptr %v7, align 8, !tbaa !16, !noalias !29
  %v86 = icmp eq ptr %v85, null
  br i1 %v86, label %v103, label %v87

v87:
  %v88 = load ptr, ptr %v85, align 8, !tbaa !41
  %v89 = getelementptr inbounds ptr, ptr %v88, i64 1
  %v90 = load ptr, ptr %v89, align 8
  call void %v90(ptr noundef nonnull align 8 dereferenceable(176) %v85) #24
  br label %v103

v91:
  %v92 = landingpad { ptr, i32 }
          cleanup
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v5) #27, !noalias !29
  br label %v101

v93:
  %v94 = landingpad { ptr, i32 }
          cleanup
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v6) #27, !noalias !29
  br label %v101

v95:
  %v96 = landingpad { ptr, i32 }
          cleanup
  br label %v101

v97:
  %v98 = landingpad { ptr, i32 }
          cleanup
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v8) #27, !noalias !29
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v7) #27, !noalias !29
  br label %v101

v99:
  %v100 = phi { ptr, i32 } [ %v102, %v101 ], [ %v153, %v152 ]
  resume { ptr, i32 } %v100

v101:
  %v102 = phi { ptr, i32 } [ %v98, %v97 ], [ %v96, %v95 ], [ %v94, %v93 ], [ %v92, %v91 ]
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v4) #27, !noalias !29
  call fastcc void @_ZN12_GLOBAL__N_115aarch64_asm_ctxD2Ev(ptr noundef nonnull align 8 dereferenceable(32) %v9) #24
  br label %v99

v103:
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v8) #27, !noalias !29
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v7) #27, !noalias !29
  %v104 = load ptr, ptr %v26, align 8, !tbaa !16, !alias.scope !29
  %v105 = load ptr, ptr %v25, align 8, !tbaa !16, !alias.scope !29
  call void @_ZN6asmjit5v1_1611BaseEmitter15setErrorHandlerEPNS0_12ErrorHandlerE(ptr noundef nonnull align 8 dereferenceable(144) %v104, ptr noundef %v105) #24
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v4) #27, !noalias !29
  %v106 = load ptr, ptr %v26, align 8, !tbaa !16
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %v10) #27
  %v107 = load ptr, ptr %v106, align 8, !tbaa !41
  %v108 = getelementptr inbounds ptr, ptr %v107, i64 4
  %v109 = load ptr, ptr %v108, align 8
  invoke void %v109(ptr nonnull sret(%"class.asmjit::v1_16::Label") align 4 %v10, ptr noundef nonnull align 8 dereferenceable(176) %v106) #25
          to label %v110 unwind label %v144

v110:
  invoke void @_ZN13kernel_module27arm64_module_asm_func_startEPN6asmjit5v1_163a649AssemblerE(ptr noundef nonnull %v106) #25
          to label %v111 unwind label %v144

v111:
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %v3) #27
  store i32 4, ptr %v3, align 4, !tbaa !49
  store i32 0, ptr %v27, align 4, !tbaa !51
  store i32 936, ptr %v28, align 4, !tbaa !27
  store i32 0, ptr %v29, align 4, !tbaa !27
  %v112 = invoke noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE2icERKNS0_3ImmERKNS1_2GpE(ptr noundef nonnull align 1 dereferenceable(1) %v106, ptr noundef nonnull align 4 dereferenceable(16) %v3, ptr noundef nonnull align 4 dereferenceable(16) @_ZN6asmjit5v1_163a644regsL3xzrE) #25
          to label %v113 unwind label %v144

v113:
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %v3) #27
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %v2) #27
  store i32 4, ptr %v2, align 4, !tbaa !49
  store i32 0, ptr %v30, align 4, !tbaa !51
  store i32 11, ptr %v31, align 4, !tbaa !27
  store i32 0, ptr %v32, align 4, !tbaa !27
  %v114 = invoke noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3dsbERKNS0_3ImmE(ptr noundef nonnull align 1 dereferenceable(1) %v106, ptr noundef nonnull align 4 dereferenceable(16) %v2) #25
          to label %v115 unwind label %v144

v115:
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %v2) #27
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %v1) #27
  store i32 4, ptr %v1, align 4, !tbaa !49
  store i32 0, ptr %v33, align 4, !tbaa !51
  store i32 15, ptr %v34, align 4, !tbaa !27
  store i32 0, ptr %v35, align 4, !tbaa !27
  %v116 = invoke noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3isbERKNS0_3ImmE(ptr noundef nonnull align 1 dereferenceable(1) %v106, ptr noundef nonnull align 4 dereferenceable(16) %v1) #25
          to label %v117 unwind label %v144

v117:
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %v1) #27
  invoke void @_ZN13kernel_module25arm64_module_asm_func_endEPN6asmjit5v1_163a649AssemblerE(ptr noundef nonnull %v106) #25
          to label %v118 unwind label %v144

v118:
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %v11) #27
  call void @llvm.experimental.noalias.scope.decl(metadata !53)
  %v119 = getelementptr inbounds %"class.asmjit::v1_16::BaseEmitter", ptr %v106, i64 0, i32 13
  %v120 = load ptr, ptr %v119, align 8, !tbaa !56, !noalias !53
  %v121 = icmp eq ptr %v120, null
  br i1 %v121, label %v141, label %v122

v122:
  %v123 = getelementptr inbounds %"class.(anonymous namespace)::MyAsmJitErrorHandler", ptr %v120, i64 0, i32 1
  %v124 = load i8, ptr %v123, align 8, !tbaa !46, !range !67, !noalias !53, !noundef !68
  %v125 = icmp eq i8 %v124, 0
  br i1 %v125, label %v126, label %v141

v126:
  %v127 = getelementptr inbounds %"class.asmjit::v1_16::BaseEmitter", ptr %v106, i64 0, i32 11
  %v128 = load ptr, ptr %v127, align 8, !tbaa !69, !noalias !53
  %v129 = icmp eq ptr %v128, null
  br i1 %v129, label %v141, label %v130

v130:
  %v131 = getelementptr inbounds %"class.asmjit::v1_16::CodeHolder", ptr %v128, i64 0, i32 8
  %v132 = load ptr, ptr %v131, align 8, !tbaa !70, !noalias !53
  %v133 = load ptr, ptr %v132, align 8, !tbaa !16, !noalias !53
  %v134 = icmp eq ptr %v133, null
  br i1 %v134, label %v141, label %v135

v135:
  %v136 = getelementptr inbounds %"class.asmjit::v1_16::Section", ptr %v133, i64 0, i32 7
  %v137 = load ptr, ptr %v136, align 8, !tbaa !72, !noalias !53
  %v138 = getelementptr inbounds %"class.asmjit::v1_16::Section", ptr %v133, i64 0, i32 7, i32 1
  %v139 = load i64, ptr %v138, align 8, !tbaa !75, !noalias !53
  %v140 = getelementptr inbounds i8, ptr %v137, i64 %v139
  invoke void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEEC2IPKhLi0EEET_S7_(ptr noundef nonnull align 8 dereferenceable(24) %v11, ptr noundef %v137, ptr noundef %v140) #25
          to label %v142 unwind label %v146

v141:
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(24) %v11, i8 0, i64 24, i1 false), !alias.scope !53
  br label %v142

v142:
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %v12) #27
  store i64 0, ptr %v12, align 8, !tbaa !76
  %v143 = invoke noundef i64 @_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm(ptr noundef nonnull align 8 dereferenceable(24) %v11, ptr noundef nonnull align 8 dereferenceable(8) %v12) #25
          to label %v154 unwind label %v148

v144:
  %v145 = landingpad { ptr, i32 }
          cleanup
  br label %v152

v146:
  %v147 = landingpad { ptr, i32 }
          cleanup
  br label %v150

v148:
  %v149 = landingpad { ptr, i32 }
          cleanup
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v12) #27
  call void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %v11) #24
  br label %v150

v150:
  %v151 = phi { ptr, i32 } [ %v149, %v148 ], [ %v147, %v146 ]
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %v11) #27
  br label %v152

v152:
  %v153 = phi { ptr, i32 } [ %v151, %v150 ], [ %v145, %v144 ]
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %v10) #27
  call fastcc void @_ZN12_GLOBAL__N_115aarch64_asm_ctxD2Ev(ptr noundef nonnull align 8 dereferenceable(32) %v9) #24
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %v9) #27
  br label %v99

v154:
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %v12) #27
  call void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %v11) #24
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %v11) #27
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %v10) #27
  call fastcc void @_ZN12_GLOBAL__N_115aarch64_asm_ctxD2Ev(ptr noundef nonnull align 8 dereferenceable(32) %v9) #24
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %v9) #27
  ret i64 %v143
}

; Function Attrs: minsize optsize
declare i32 @sched_getcpu() local_unnamed_addr #8

; Function Attrs: minsize nofree nounwind optsize
declare noundef i32 @fprintf(ptr nocapture noundef, ptr nocapture noundef readonly, ...) local_unnamed_addr #7

; Function Attrs: minsize optsize
declare ptr @strerror(i32 noundef) local_unnamed_addr #8

; Function Attrs: minsize mustprogress nofree nosync nounwind optsize willreturn memory(none)
declare ptr @__errno() local_unnamed_addr #9

; Function Attrs: minsize optsize
declare i64 @sysconf(i32 noundef) local_unnamed_addr #8

; Function Attrs: minsize mustprogress optsize uwtable
define internal fastcc noundef i1 @_ZN13kernel_moduleL14set_thread_cpuEi(i32 noundef %0) unnamed_addr #6 {
  %2 = alloca %struct.cpu_set_t, align 8
  %3 = icmp ugt i32 %0, 1023
  br i1 %3, label %4, label %6

4:                                                ; preds = %1
  %5 = tail call i32 (ptr, ptr, ...) @fprintf(ptr noundef nonnull getelementptr inbounds ([0 x %struct.__sFILE], ptr @__sF, i64 0, i64 2), ptr noundef nonnull @.str.20, i32 noundef %0) #25
  br label %23

6:                                                ; preds = %1
  call void @llvm.lifetime.start.p0(i64 128, ptr nonnull %2) #27
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(128) %2, i8 0, i64 128, i1 false)
  %7 = zext i32 %0 to i64
  %8 = and i64 %7, 63
  %9 = shl nuw i64 1, %8
  %10 = lshr i64 %7, 6
  %11 = getelementptr inbounds [16 x i64], ptr %2, i64 0, i64 %10
  %12 = load i64, ptr %11, align 8, !tbaa !76
  %13 = or i64 %12, %9
  store i64 %13, ptr %11, align 8, !tbaa !76
  %14 = call i32 @sched_setaffinity(i32 noundef 0, i64 noundef 128, ptr noundef nonnull %2) #25
  %15 = icmp eq i32 %14, 0
  br i1 %15, label %21, label %16

16:                                               ; preds = %6
  %17 = tail call ptr @__errno() #29
  %18 = load i32, ptr %17, align 4, !tbaa !27
  %19 = call ptr @strerror(i32 noundef %18) #25
  %20 = call i32 (ptr, ptr, ...) @fprintf(ptr noundef nonnull getelementptr inbounds ([0 x %struct.__sFILE], ptr @__sF, i64 0, i64 2), ptr noundef nonnull @.str.21, i32 noundef %0, ptr noundef %19) #25
  br label %22

21:                                               ; preds = %6
  fence seq_cst
  br label %22

22:                                               ; preds = %21, %16
  call void @llvm.lifetime.end.p0(i64 128, ptr nonnull %2) #27
  br label %23

23:                                               ; preds = %22, %4
  %24 = phi i1 [ false, %4 ], [ %15, %22 ]
  ret i1 %24
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite)
declare void @llvm.assume(i1 noundef) #10

; Function Attrs: inlinehint minsize optsize uwtable
define available_externally void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1, i64 noundef %2) local_unnamed_addr #3 align 2 personality ptr @__gxx_personality_v0 {
  %4 = icmp ugt i64 %2, -17
  br i1 %4, label %5, label %6

5:                                                ; preds = %3
  tail call void @_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #31
  unreachable

6:                                                ; preds = %3
  %7 = icmp ult i64 %2, 23
  br i1 %7, label %8, label %12

8:                                                ; preds = %6
  %9 = trunc i64 %2 to i8
  %10 = shl nuw nsw i8 %9, 1
  store i8 %10, ptr %0, align 8
  %11 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__short", ptr %0, i64 0, i32 2
  br label %22

12:                                               ; preds = %6
  %13 = or i64 %2, 15
  %14 = add i64 %13, 1
  %15 = tail call [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %14) #25
  %16 = extractvalue [2 x i64] %15, 0
  %17 = inttoptr i64 %16 to ptr
  %18 = extractvalue [2 x i64] %15, 1
  %19 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 2
  store ptr %17, ptr %19, align 8, !tbaa !12
  %20 = or i64 %18, 1
  store i64 %20, ptr %0, align 8
  %21 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 1
  store i64 %2, ptr %21, align 8, !tbaa !12
  br label %22

22:                                               ; preds = %12, %8
  %23 = phi ptr [ %11, %8 ], [ %17, %12 ]
  %24 = icmp ugt ptr %23, %1
  %25 = getelementptr inbounds i8, ptr %23, i64 %2
  %26 = icmp ule ptr %25, %1
  %27 = or i1 %24, %26
  tail call void @llvm.assume(i1 %27)
  tail call void @llvm.memmove.p0.p0.i64(ptr align 1 %23, ptr align 1 %1, i64 %2, i1 false)
  store i8 0, ptr %25, align 1, !tbaa !12
  ret void
}

; Function Attrs: minsize mustprogress noreturn optsize uwtable
define linkonce_odr hidden void @_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) local_unnamed_addr #11 comdat align 2 {
  tail call void @_ZNSt6__ndk120__throw_length_errorB7v170000EPKc(ptr noundef nonnull @.str.18) #31
  unreachable
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %1) local_unnamed_addr #6 comdat {
  %3 = tail call noalias noundef nonnull ptr @_Znwm(i64 noundef %1) #30
  %4 = ptrtoint ptr %3 to i64
  %5 = insertvalue [2 x i64] poison, i64 %4, 0
  %6 = insertvalue [2 x i64] %5, i64 %1, 1
  ret [2 x i64] %6
}

; Function Attrs: inlinehint minsize mustprogress noreturn optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk120__throw_length_errorB7v170000EPKc(ptr noundef %0) local_unnamed_addr #12 comdat personality ptr @__gxx_personality_v0 {
  %2 = tail call ptr @__cxa_allocate_exception(i64 16) #27
  invoke void @_ZNSt12length_errorC2B7v170000EPKc(ptr noundef nonnull align 8 dereferenceable(16) %2, ptr noundef %0) #25
          to label %3 unwind label %4

3:                                                ; preds = %1
  tail call void @__cxa_throw(ptr nonnull %2, ptr nonnull @_ZTISt12length_error, ptr nonnull @_ZNSt12length_errorD1Ev) #32
  unreachable

4:                                                ; preds = %1
  %5 = landingpad { ptr, i32 }
          cleanup
  tail call void @__cxa_free_exception(ptr %2) #27
  resume { ptr, i32 } %5
}

declare ptr @__cxa_allocate_exception(i64) local_unnamed_addr

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt12length_errorC2B7v170000EPKc(ptr noundef nonnull align 8 dereferenceable(16) %0, ptr noundef %1) unnamed_addr #1 comdat align 2 {
  tail call void @_ZNSt11logic_errorC2EPKc(ptr noundef nonnull align 8 dereferenceable(16) %0, ptr noundef %1) #25
  store ptr getelementptr inbounds ({ [5 x ptr] }, ptr @_ZTVSt12length_error, i64 0, inrange i32 0, i64 2), ptr %0, align 8, !tbaa !41
  ret void
}

declare void @__cxa_free_exception(ptr) local_unnamed_addr

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt12length_errorD1Ev(ptr noundef nonnull align 8 dereferenceable(16)) unnamed_addr #13

declare void @__cxa_throw(ptr, ptr, ptr) local_unnamed_addr

; Function Attrs: minsize optsize
declare void @_ZNSt11logic_errorC2EPKc(ptr noundef nonnull align 8 dereferenceable(16), ptr noundef) unnamed_addr #8

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt12length_errorD0Ev(ptr noundef nonnull align 8 dereferenceable(16)) unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare noundef ptr @_ZNKSt11logic_error4whatEv(ptr noundef nonnull align 8 dereferenceable(16)) unnamed_addr #13

; Function Attrs: inlinehint minsize mustprogress noreturn optsize uwtable
define linkonce_odr hidden void @_ZSt28__throw_bad_array_new_lengthB7v170000v() local_unnamed_addr #12 comdat {
  %1 = tail call ptr @__cxa_allocate_exception(i64 8) #27
  tail call void @_ZNSt20bad_array_new_lengthC1Ev(ptr noundef nonnull align 8 dereferenceable(8) %1) #24
  tail call void @__cxa_throw(ptr nonnull %1, ptr nonnull @_ZTISt20bad_array_new_length, ptr nonnull @_ZNSt20bad_array_new_lengthD1Ev) #32
  unreachable
}

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt20bad_array_new_lengthC1Ev(ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt20bad_array_new_lengthD1Ev(ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #13

; Function Attrs: minsize nobuiltin optsize allocsize(0)
declare noundef nonnull ptr @_Znwm(i64 noundef) local_unnamed_addr #14

; Function Attrs: minsize noinline noreturn nounwind optsize
define linkonce_odr hidden void @__clang_call_terminate(ptr noundef %0) local_unnamed_addr #15 comdat {
  %2 = tail call ptr @__cxa_begin_catch(ptr %0) #27
  tail call void @_ZSt9terminatev() #28
  unreachable
}

declare ptr @__cxa_begin_catch(ptr) local_unnamed_addr

declare void @_ZSt9terminatev() local_unnamed_addr

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memmove.p0.p0.i64(ptr nocapture writeonly, ptr nocapture readonly, i64, i1 immarg) #16

; Function Attrs: minsize mustprogress nofree nounwind optsize willreturn memory(argmem: read)
declare i64 @strlen(ptr nocapture noundef) local_unnamed_addr #17

; Function Attrs: minsize nobuiltin nounwind optsize
declare void @_ZdlPv(ptr noundef) local_unnamed_addr #18

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE11__vallocateB7v170000Em(ptr noundef nonnull align 8 dereferenceable(24) %0, i64 noundef %1) local_unnamed_addr #6 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = icmp ugt i64 %1, 768614336404564650
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  tail call void @_ZNKSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #31
  unreachable

5:                                                ; preds = %2
  %6 = getelementptr inbounds %"class.std::__ndk1::vector", ptr %0, i64 0, i32 2
  %7 = tail call [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERSA_m(ptr noundef nonnull align 1 dereferenceable(1) %6, i64 noundef %1) #25
  %8 = extractvalue [2 x i64] %7, 0
  %9 = inttoptr i64 %8 to ptr
  %10 = extractvalue [2 x i64] %7, 1
  store ptr %9, ptr %0, align 8, !tbaa !79
  %11 = getelementptr inbounds %"class.std::__ndk1::vector", ptr %0, i64 0, i32 1
  store ptr %9, ptr %11, align 8, !tbaa !83
  %12 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %9, i64 %10
  store ptr %12, ptr %6, align 8, !tbaa !16
  ret void
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE18__construct_at_endIPKS6_Li0EEEvT_SC_m(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1, ptr noundef %2, i64 noundef %3) local_unnamed_addr #1 comdat align 2 personality ptr @__gxx_personality_v0 {
  %5 = getelementptr inbounds %"class.std::__ndk1::vector", ptr %0, i64 0, i32 1
  %6 = load ptr, ptr %5, align 8, !tbaa !83
  %7 = getelementptr inbounds %"class.std::__ndk1::vector", ptr %0, i64 0, i32 2
  %8 = invoke noundef ptr @_ZNSt6__ndk130__uninitialized_allocator_copyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPKS6_S9_PS6_EET2_RT_T0_T1_SB_(ptr noundef nonnull align 1 dereferenceable(1) %7, ptr noundef %1, ptr noundef %2, ptr noundef %6) #25
          to label %9 unwind label %10

9:                                                ; preds = %4
  store ptr %8, ptr %5, align 8, !tbaa !83
  ret void

10:                                               ; preds = %4
  %11 = landingpad { ptr, i32 }
          cleanup
  store ptr %6, ptr %5, align 8, !tbaa !83
  resume { ptr, i32 } %11
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk117__exception_guardINS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %0) unnamed_addr #4 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard", ptr %0, i64 0, i32 1
  %3 = load i8, ptr %2, align 8, !tbaa !21, !range !67, !noundef !68
  %4 = icmp eq i8 %3, 0
  br i1 %4, label %5, label %6

5:                                                ; preds = %1
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) #25
          to label %6 unwind label %7

6:                                                ; preds = %5, %1
  ret void

7:                                                ; preds = %5
  %8 = landingpad { ptr, i32 }
          catch ptr null
  %9 = extractvalue { ptr, i32 } %8, 0
  tail call void @__clang_call_terminate(ptr %9) #28
  unreachable
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #16

; Function Attrs: minsize mustprogress noreturn optsize uwtable
define linkonce_odr hidden void @_ZNKSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) local_unnamed_addr #11 comdat align 2 {
  tail call void @_ZNSt6__ndk120__throw_length_errorB7v170000EPKc(ptr noundef nonnull @.str.19) #31
  unreachable
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERSA_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %1) local_unnamed_addr #6 comdat {
  %3 = tail call noundef ptr @_ZNSt6__ndk19allocatorINS_12basic_stringIcNS_11char_traitsIcEENS0_IcEEEEE8allocateB7v170000Em(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %1) #25
  %4 = ptrtoint ptr %3 to i64
  %5 = insertvalue [2 x i64] poison, i64 %4, 0
  %6 = insertvalue [2 x i64] %5, i64 %1, 1
  ret [2 x i64] %6
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef ptr @_ZNSt6__ndk19allocatorINS_12basic_stringIcNS_11char_traitsIcEENS0_IcEEEEE8allocateB7v170000Em(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %1) local_unnamed_addr #6 comdat align 2 {
  %3 = icmp ugt i64 %1, 768614336404564650
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  tail call void @_ZSt28__throw_bad_array_new_lengthB7v170000v() #31
  unreachable

5:                                                ; preds = %2
  %6 = mul nuw i64 %1, 24
  %7 = tail call noalias noundef nonnull ptr @_Znwm(i64 noundef %6) #30
  ret ptr %7
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden noundef ptr @_ZNSt6__ndk130__uninitialized_allocator_copyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPKS6_S9_PS6_EET2_RT_T0_T1_SB_(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef %1, ptr noundef %2, ptr noundef %3) local_unnamed_addr #1 comdat personality ptr @__gxx_personality_v0 {
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca %"struct.std::__ndk1::__exception_guard.10", align 8
  store ptr %3, ptr %5, align 8, !tbaa !16
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %6) #27
  store ptr %3, ptr %6, align 8, !tbaa !16
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %7) #27
  store ptr %0, ptr %7, align 8
  %8 = getelementptr inbounds i8, ptr %7, i64 8
  store ptr %6, ptr %8, align 8
  %9 = getelementptr inbounds i8, ptr %7, i64 16
  store ptr %5, ptr %9, align 8
  %10 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard.10", ptr %7, i64 0, i32 1
  store i8 0, ptr %10, align 8, !tbaa !84, !alias.scope !87
  br label %11

11:                                               ; preds = %16, %4
  %12 = phi ptr [ %3, %4 ], [ %19, %16 ]
  %13 = phi ptr [ %1, %4 ], [ %17, %16 ]
  %14 = icmp eq ptr %13, %2
  br i1 %14, label %22, label %15

15:                                               ; preds = %11
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_(ptr noundef nonnull align 8 dereferenceable(24) %12, ptr noundef nonnull align 8 dereferenceable(24) %13) #25
          to label %16 unwind label %20

16:                                               ; preds = %15
  %17 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %13, i64 1
  %18 = load ptr, ptr %5, align 8, !tbaa !16
  %19 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %18, i64 1
  store ptr %19, ptr %5, align 8, !tbaa !16
  br label %11, !llvm.loop !90

20:                                               ; preds = %15
  %21 = landingpad { ptr, i32 }
          cleanup
  call void @_ZNSt6__ndk117__exception_guardINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(25) %7) #24
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %7) #27
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %6) #27
  resume { ptr, i32 } %21

22:                                               ; preds = %11
  store i8 1, ptr %10, align 8, !tbaa !84
  call void @_ZNSt6__ndk117__exception_guardINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(25) %7) #24
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %7) #27
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %6) #27
  ret ptr %12
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk117__exception_guardINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(25) %0) unnamed_addr #4 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard.10", ptr %0, i64 0, i32 1
  %3 = load i8, ptr %2, align 8, !tbaa !84, !range !67, !noundef !68
  %4 = icmp eq i8 %3, 0
  br i1 %4, label %5, label %6

5:                                                ; preds = %1
  invoke void @_ZNKSt6__ndk129_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPS6_EclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #25
          to label %6 unwind label %7

6:                                                ; preds = %5, %1
  ret void

7:                                                ; preds = %5
  %8 = landingpad { ptr, i32 }
          catch ptr null
  %9 = extractvalue { ptr, i32 } %8, 0
  tail call void @__clang_call_terminate(ptr %9) #28
  unreachable
}

; Function Attrs: minsize optsize uwtable
define available_externally void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef nonnull align 8 dereferenceable(24) %1) unnamed_addr #1 align 2 {
  %3 = load i8, ptr %1, align 8
  %4 = and i8 %3, 1
  %5 = icmp eq i8 %4, 0
  br i1 %5, label %6, label %7

6:                                                ; preds = %2
  tail call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef nonnull align 8 dereferenceable(24) %1, i64 24, i1 false), !tbaa.struct !91
  br label %12

7:                                                ; preds = %2
  %8 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %1, i64 0, i32 2
  %9 = load ptr, ptr %8, align 8, !tbaa !12
  %10 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %1, i64 0, i32 1
  %11 = load i64, ptr %10, align 8, !tbaa !12
  tail call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE25__init_copy_ctor_externalEPKcm(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %9, i64 noundef %11) #25
  br label %12

12:                                               ; preds = %7, %6
  ret void
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE25__init_copy_ctor_externalEPKcm(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1, i64 noundef %2) local_unnamed_addr #1 comdat align 2 personality ptr @__gxx_personality_v0 {
  %4 = icmp ult i64 %2, 23
  br i1 %4, label %5, label %9

5:                                                ; preds = %3
  %6 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__short", ptr %0, i64 0, i32 2
  %7 = trunc i64 %2 to i8
  %8 = shl nuw nsw i8 %7, 1
  store i8 %8, ptr %0, align 8
  br label %22

9:                                                ; preds = %3
  %10 = icmp ugt i64 %2, -17
  br i1 %10, label %11, label %12

11:                                               ; preds = %9
  tail call void @_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #31
  unreachable

12:                                               ; preds = %9
  %13 = or i64 %2, 15
  %14 = add i64 %13, 1
  %15 = tail call [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %14) #25
  %16 = extractvalue [2 x i64] %15, 0
  %17 = inttoptr i64 %16 to ptr
  %18 = extractvalue [2 x i64] %15, 1
  %19 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 2
  store ptr %17, ptr %19, align 8, !tbaa !12
  %20 = or i64 %18, 1
  store i64 %20, ptr %0, align 8
  %21 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 1
  store i64 %2, ptr %21, align 8, !tbaa !12
  br label %22

22:                                               ; preds = %12, %5
  %23 = phi ptr [ %6, %5 ], [ %17, %12 ]
  %24 = add nuw i64 %2, 1
  %25 = icmp ugt ptr %23, %1
  %26 = getelementptr inbounds i8, ptr %23, i64 %24
  %27 = icmp ule ptr %26, %1
  %28 = select i1 %25, i1 true, i1 %27
  tail call void @llvm.assume(i1 %28)
  tail call void @llvm.memmove.p0.p0.i64(ptr align 1 %23, ptr align 1 %1, i64 %24, i1 false)
  ret void
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNKSt6__ndk129_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPS6_EclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) local_unnamed_addr #1 comdat align 2 !type !92 {
  %2 = load ptr, ptr %0, align 8, !tbaa !93
  %3 = getelementptr inbounds %"class.std::__ndk1::_AllocatorDestroyRangeReverse", ptr %0, i64 0, i32 2
  %4 = load ptr, ptr %3, align 8, !tbaa !94
  %5 = load ptr, ptr %4, align 8, !tbaa !16
  %6 = getelementptr inbounds %"class.std::__ndk1::_AllocatorDestroyRangeReverse", ptr %0, i64 0, i32 1
  %7 = load ptr, ptr %6, align 8, !tbaa !95
  %8 = load ptr, ptr %7, align 8, !tbaa !16
  %9 = ptrtoint ptr %5 to i64
  %10 = insertvalue [2 x i64] poison, i64 %9, 0
  %11 = insertvalue [2 x i64] %10, i64 %9, 1
  %12 = ptrtoint ptr %8 to i64
  %13 = insertvalue [2 x i64] poison, i64 %12, 0
  %14 = insertvalue [2 x i64] %13, i64 %12, 1
  tail call void @_ZNSt6__ndk119__allocator_destroyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEENS_16reverse_iteratorIPS6_EESA_EEvRT_T0_T1_(ptr noundef nonnull align 1 dereferenceable(1) %2, [2 x i64] %11, [2 x i64] %14) #25
  ret void
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk119__allocator_destroyB7v170000INS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEENS_16reverse_iteratorIPS6_EESA_EEvRT_T0_T1_(ptr noundef nonnull align 1 dereferenceable(1) %0, [2 x i64] %1, [2 x i64] %2) local_unnamed_addr #6 comdat personality ptr @__gxx_personality_v0 {
  %4 = extractvalue [2 x i64] %1, 1
  %5 = inttoptr i64 %4 to ptr
  %6 = extractvalue [2 x i64] %2, 1
  %7 = inttoptr i64 %6 to ptr
  br label %8

8:                                                ; preds = %11, %3
  %9 = phi ptr [ %5, %3 ], [ %12, %11 ]
  %10 = icmp eq ptr %9, %7
  br i1 %10, label %13, label %11

11:                                               ; preds = %8
  %12 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %9, i64 -1
  tail call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %12) #24
  br label %8, !llvm.loop !96

13:                                               ; preds = %8
  ret void
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) local_unnamed_addr #6 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = load ptr, ptr %0, align 8, !tbaa !97
  %3 = load ptr, ptr %2, align 8, !tbaa !79
  %4 = icmp eq ptr %3, null
  br i1 %4, label %8, label %5

5:                                                ; preds = %1
  tail call void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE7__clearB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %2) #24
  %6 = load ptr, ptr %0, align 8, !tbaa !97
  %7 = load ptr, ptr %6, align 8, !tbaa !79
  tail call void @_ZdlPv(ptr noundef %7) #26
  br label %8

8:                                                ; preds = %5, %1
  ret void
}

; Function Attrs: minsize mustprogress nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE7__clearB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) local_unnamed_addr #19 comdat align 2 {
  %2 = load ptr, ptr %0, align 8, !tbaa !79
  tail call void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE22__base_destruct_at_endB7v170000EPS6_(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %2) #24
  ret void
}

; Function Attrs: minsize mustprogress nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE22__base_destruct_at_endB7v170000EPS6_(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1) local_unnamed_addr #19 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = getelementptr inbounds %"class.std::__ndk1::vector", ptr %0, i64 0, i32 1
  %4 = load ptr, ptr %3, align 8, !tbaa !83
  br label %5

5:                                                ; preds = %8, %2
  %6 = phi ptr [ %4, %2 ], [ %9, %8 ]
  %7 = icmp eq ptr %6, %1
  br i1 %7, label %10, label %8

8:                                                ; preds = %5
  %9 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %6, i64 -1
  tail call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %9) #24
  br label %5

10:                                               ; preds = %5
  store ptr %1, ptr %3, align 8, !tbaa !83
  ret void
}

; Function Attrs: minsize nofree optsize
declare i64 @__strlen_chk(ptr noundef, i64 noundef) local_unnamed_addr #20

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #21

; Function Attrs: minsize optsize
declare i32 @sched_setaffinity(i32 noundef, i64 noundef, ptr noundef) local_unnamed_addr #8

; Function Attrs: minsize optsize
declare void @_ZN13kernel_module27arm64_module_asm_func_startEPN6asmjit5v1_163a649AssemblerE(ptr noundef) local_unnamed_addr #8

; Function Attrs: minsize optsize
declare void @_ZN13kernel_module25arm64_module_asm_func_endEPN6asmjit5v1_163a649AssemblerE(ptr noundef) local_unnamed_addr #8

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i64 @_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef nonnull align 8 dereferenceable(8) %1) local_unnamed_addr #22 comdat {
  %3 = load ptr, ptr %0, align 8, !tbaa !98
  %4 = getelementptr inbounds %"class.std::__ndk1::vector.41", ptr %0, i64 0, i32 1
  %5 = load ptr, ptr %4, align 8, !tbaa !102
  %6 = ptrtoint ptr %5 to i64
  %7 = ptrtoint ptr %3 to i64
  %8 = sub i64 %6, %7
  %9 = trunc i64 %8 to i32
  %10 = tail call noundef i64 @_ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm(ptr noundef %3, i32 noundef %9, ptr noundef nonnull align 8 dereferenceable(8) %1) #25
  ret i64 %10
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) unnamed_addr #4 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = alloca %"class.std::__ndk1::vector<unsigned char>::__destroy_vector", align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2) #27
  store ptr %0, ptr %2, align 8, !tbaa !16
  invoke void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %2) #25
          to label %3 unwind label %4

3:                                                ; preds = %1
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %2) #27
  ret void

4:                                                ; preds = %1
  %5 = landingpad { ptr, i32 }
          catch ptr null
  %6 = extractvalue { ptr, i32 } %5, 0
  call void @__clang_call_terminate(ptr %6) #28
  unreachable
}

; Function Attrs: inlinehint minsize nounwind optsize uwtable
define internal fastcc void @_ZN12_GLOBAL__N_115aarch64_asm_ctxD2Ev(ptr noundef nonnull align 8 dereferenceable(32) %0) unnamed_addr #2 align 2 {
  %2 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %0, i64 0, i32 3
  tail call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_163a649AssemblerENS_14default_deleteIS4_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %2) #24
  %3 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %0, i64 0, i32 2
  tail call fastcc void @_ZNSt6__ndk110unique_ptrIN12_GLOBAL__N_120MyAsmJitErrorHandlerENS_14default_deleteIS2_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %3) #24
  %4 = getelementptr inbounds %"struct.(anonymous namespace)::aarch64_asm_ctx", ptr %0, i64 0, i32 1
  tail call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %4) #24
  tail call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1612StringLoggerENS_14default_deleteIS3_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) #24
  ret void
}

; Function Attrs: inlinehint minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1610CodeHolderEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr noalias sret(%"class.std::__ndk1::unique_ptr.17") align 8 %0) local_unnamed_addr #3 comdat personality ptr @__gxx_personality_v0 {
  %2 = tail call noalias noundef nonnull dereferenceable(344) ptr @_Znwm(i64 noundef 344) #30
  tail call void @_ZN6asmjit5v1_1610CodeHolderC1EPKNS0_7Support9TemporaryE(ptr noundef nonnull align 8 dereferenceable(344) %2, ptr noundef null) #24
  store ptr %2, ptr %0, align 8, !tbaa !103
  ret void
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) unnamed_addr #4 comdat align 2 {
  tail call void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEE5resetB7v170000EPS3_(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef null) #24
  ret void
}

; Function Attrs: minsize nounwind optsize
declare noundef i32 @_ZN6asmjit5v1_1610CodeHolder4initERKNS0_11EnvironmentEm(ptr noundef nonnull align 8 dereferenceable(344), ptr noundef nonnull align 1 dereferenceable(8), i64 noundef) local_unnamed_addr #13

; Function Attrs: inlinehint minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_1612StringLoggerEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr noalias sret(%"class.std::__ndk1::unique_ptr") align 8 %0) local_unnamed_addr #3 comdat personality ptr @__gxx_personality_v0 {
  %2 = tail call noalias noundef nonnull dereferenceable(56) ptr @_Znwm(i64 noundef 56) #30
  tail call void @_ZN6asmjit5v1_1612StringLoggerC1Ev(ptr noundef nonnull align 8 dereferenceable(56) %2) #24
  store ptr %2, ptr %0, align 8, !tbaa !105
  ret void
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1612StringLoggerENS_14default_deleteIS3_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) unnamed_addr #4 comdat align 2 {
  %2 = load ptr, ptr %0, align 8, !tbaa !16
  store ptr null, ptr %0, align 8, !tbaa !16
  %3 = icmp eq ptr %2, null
  br i1 %3, label %8, label %4

4:                                                ; preds = %1
  %5 = load ptr, ptr %2, align 8, !tbaa !41
  %6 = getelementptr inbounds ptr, ptr %5, i64 1
  %7 = load ptr, ptr %6, align 8
  tail call void %7(ptr noundef nonnull align 8 dereferenceable(56) %2) #24
  br label %8

8:                                                ; preds = %4, %1
  ret void
}

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1610CodeHolder9setLoggerEPNS0_6LoggerE(ptr noundef nonnull align 8 dereferenceable(344), ptr noundef) local_unnamed_addr #13

; Function Attrs: minsize nounwind optsize uwtable
define internal fastcc void @_ZNSt6__ndk110unique_ptrIN12_GLOBAL__N_120MyAsmJitErrorHandlerENS_14default_deleteIS2_EEED2B7v170000Ev(ptr nocapture noundef nonnull align 8 dereferenceable(8) %0) unnamed_addr #4 align 2 {
  %2 = load ptr, ptr %0, align 8, !tbaa !16
  store ptr null, ptr %0, align 8, !tbaa !16
  %3 = icmp eq ptr %2, null
  br i1 %3, label %8, label %4

4:                                                ; preds = %1
  %5 = load ptr, ptr %2, align 8, !tbaa !41
  %6 = getelementptr inbounds ptr, ptr %5, i64 1
  %7 = load ptr, ptr %6, align 8
  tail call void %7(ptr noundef nonnull align 8 dereferenceable(9) %2) #24
  br label %8

8:                                                ; preds = %4, %1
  ret void
}

; Function Attrs: inlinehint minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk111make_uniqueB7v170000IN6asmjit5v1_163a649AssemblerEJPNS2_10CodeHolderEEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_(ptr noalias sret(%"class.std::__ndk1::unique_ptr.33") align 8 %0, ptr noundef nonnull align 8 dereferenceable(8) %1) local_unnamed_addr #3 comdat personality ptr @__gxx_personality_v0 {
  %3 = tail call noalias noundef nonnull dereferenceable(176) ptr @_Znwm(i64 noundef 176) #30
  %4 = load ptr, ptr %1, align 8, !tbaa !16
  tail call void @_ZN6asmjit5v1_163a649AssemblerC1EPNS0_10CodeHolderE(ptr noundef nonnull align 8 dereferenceable(176) %3, ptr noundef %4) #24
  store ptr %3, ptr %0, align 8, !tbaa !107
  ret void
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_163a649AssemblerENS_14default_deleteIS4_EEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) unnamed_addr #4 comdat align 2 {
  %2 = load ptr, ptr %0, align 8, !tbaa !16
  store ptr null, ptr %0, align 8, !tbaa !16
  %3 = icmp eq ptr %2, null
  br i1 %3, label %8, label %4

4:                                                ; preds = %1
  %5 = load ptr, ptr %2, align 8, !tbaa !41
  %6 = getelementptr inbounds ptr, ptr %5, i64 1
  %7 = load ptr, ptr %6, align 8
  tail call void %7(ptr noundef nonnull align 8 dereferenceable(176) %2) #24
  br label %8

8:                                                ; preds = %4, %1
  ret void
}

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1611BaseEmitter15setErrorHandlerEPNS0_12ErrorHandlerE(ptr noundef nonnull align 8 dereferenceable(144), ptr noundef) local_unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1610CodeHolderC1EPKNS0_7Support9TemporaryE(ptr noundef nonnull align 8 dereferenceable(344), ptr noundef) unnamed_addr #13

; Function Attrs: minsize mustprogress nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEE5resetB7v170000EPS3_(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef %1) local_unnamed_addr #19 comdat align 2 !type !109 {
  %3 = load ptr, ptr %0, align 8, !tbaa !16
  store ptr %1, ptr %0, align 8, !tbaa !16
  %4 = icmp eq ptr %3, null
  br i1 %4, label %6, label %5

5:                                                ; preds = %2
  tail call void @_ZNKSt6__ndk114default_deleteIN6asmjit5v1_1610CodeHolderEEclB7v170000EPS3_(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef nonnull %3) #24
  br label %6

6:                                                ; preds = %5, %2
  ret void
}

; Function Attrs: minsize mustprogress nounwind optsize uwtable
define linkonce_odr hidden void @_ZNKSt6__ndk114default_deleteIN6asmjit5v1_1610CodeHolderEEclB7v170000EPS3_(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef %1) local_unnamed_addr #19 comdat align 2 !type !110 {
  %3 = icmp eq ptr %1, null
  br i1 %3, label %5, label %4

4:                                                ; preds = %2
  tail call void @_ZN6asmjit5v1_1610CodeHolderD1Ev(ptr noundef nonnull align 8 dereferenceable(344) %1) #24
  br label %5

5:                                                ; preds = %4, %2
  tail call void @_ZdlPv(ptr noundef %1) #26
  ret void
}

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1610CodeHolderD1Ev(ptr noundef nonnull align 8 dereferenceable(344)) unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1612StringLoggerC1Ev(ptr noundef nonnull align 8 dereferenceable(56)) unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1612ErrorHandlerC2Ev(ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #13

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_1612ErrorHandlerD2Ev(ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #13

; Function Attrs: inlinehint minsize nounwind optsize uwtable
define internal void @_ZN12_GLOBAL__N_120MyAsmJitErrorHandlerD0Ev(ptr noundef nonnull align 8 dereferenceable(9) %0) unnamed_addr #2 align 2 {
  tail call void @_ZN6asmjit5v1_1612ErrorHandlerD2Ev(ptr noundef nonnull align 8 dereferenceable(9) %0) #24
  tail call void @_ZdlPv(ptr noundef nonnull %0) #26
  ret void
}

; Function Attrs: minsize mustprogress optsize uwtable
define internal void @_ZN12_GLOBAL__N_120MyAsmJitErrorHandler11handleErrorEjPKcPN6asmjit5v1_1611BaseEmitterE(ptr nocapture noundef nonnull writeonly align 8 dereferenceable(9) %0, i32 noundef %1, ptr noundef %2, ptr nocapture readnone %3) unnamed_addr #6 align 2 {
  %5 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc(ptr noundef nonnull align 8 dereferenceable(8) @_ZNSt6__ndk14cerrE, ptr noundef nonnull @.str.22) #25
  %6 = tail call noundef ptr @_ZN6asmjit5v1_1610DebugUtils13errorAsStringEj(i32 noundef %1) #24
  %7 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc(ptr noundef nonnull align 8 dereferenceable(8) %5, ptr noundef %6) #25
  %8 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc(ptr noundef nonnull align 8 dereferenceable(8) %7, ptr noundef nonnull @.str.23) #25
  %9 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc(ptr noundef nonnull align 8 dereferenceable(8) %8, ptr noundef %2) #25
  %10 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk14endlB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_(ptr noundef nonnull align 8 dereferenceable(8) %9) #25
  %11 = getelementptr inbounds %"class.(anonymous namespace)::MyAsmJitErrorHandler", ptr %0, i64 0, i32 1
  store i8 1, ptr %11, align 8, !tbaa !46
  ret void
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk1lsB7v170000INS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef %1) local_unnamed_addr #6 comdat personality ptr @__gxx_personality_v0 {
  %3 = tail call i64 @strlen(ptr noundef nonnull dereferenceable(1) %1) #24
  %4 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk124__put_character_sequenceB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef %1, i64 noundef %3) #25
  ret ptr %4
}

; Function Attrs: minsize nounwind optsize
declare noundef ptr @_ZN6asmjit5v1_1610DebugUtils13errorAsStringEj(i32 noundef) local_unnamed_addr #13

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk14endlB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_(ptr noundef nonnull align 8 dereferenceable(8) %0) local_unnamed_addr #22 comdat {
  %2 = load ptr, ptr %0, align 8, !tbaa !41
  %3 = getelementptr i8, ptr %2, i64 -24
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr inbounds i8, ptr %0, i64 %4
  %6 = tail call noundef i8 @_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE5widenB7v170000Ec(ptr noundef nonnull align 8 dereferenceable(148) %5, i8 noundef 10) #25
  %7 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE3putEc(ptr noundef nonnull align 8 dereferenceable(8) %0, i8 noundef %6) #25
  %8 = tail call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE5flushEv(ptr noundef nonnull align 8 dereferenceable(8) %0) #25
  ret ptr %0
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk124__put_character_sequenceB7v170000IcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef %1, i64 noundef %2) local_unnamed_addr #1 comdat personality ptr @__gxx_personality_v0 {
  %4 = alloca %"class.std::__ndk1::basic_ostream<char>::sentry", align 8
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %4) #27
  invoke void @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_(ptr noundef nonnull align 8 dereferenceable(16) %4, ptr noundef nonnull align 8 dereferenceable(8) %0) #25
          to label %5 unwind label %32

5:                                                ; preds = %3
  %6 = load i8, ptr %4, align 8, !tbaa !111, !range !67, !noundef !68
  %7 = icmp eq i8 %6, 0
  br i1 %7, label %38, label %8

8:                                                ; preds = %5
  %9 = load ptr, ptr %0, align 8, !tbaa !41
  %10 = getelementptr i8, ptr %9, i64 -24
  %11 = load i64, ptr %10, align 8
  %12 = getelementptr inbounds i8, ptr %0, i64 %11
  %13 = getelementptr inbounds %"class.std::__ndk1::ios_base", ptr %12, i64 0, i32 6
  %14 = load ptr, ptr %13, align 8, !tbaa !113
  %15 = getelementptr inbounds %"class.std::__ndk1::ios_base", ptr %12, i64 0, i32 1
  %16 = load i32, ptr %15, align 8, !tbaa !115
  %17 = invoke noundef i8 @_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE4fillB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(148) %12) #25
          to label %18 unwind label %36

18:                                               ; preds = %8
  %19 = and i32 %16, 176
  %20 = icmp eq i32 %19, 32
  %21 = getelementptr inbounds i8, ptr %1, i64 %2
  %22 = select i1 %20, ptr %21, ptr %1
  %23 = ptrtoint ptr %14 to i64
  %24 = invoke i64 @_ZNSt6__ndk116__pad_and_outputB7v170000IcNS_11char_traitsIcEEEENS_19ostreambuf_iteratorIT_T0_EES6_PKS4_S8_S8_RNS_8ios_baseES4_(i64 %23, ptr noundef %1, ptr noundef %22, ptr noundef %21, ptr noundef nonnull align 8 dereferenceable(136) %12, i8 noundef %17) #25
          to label %25 unwind label %36

25:                                               ; preds = %18
  %26 = icmp eq i64 %24, 0
  br i1 %26, label %27, label %38

27:                                               ; preds = %25
  %28 = load ptr, ptr %0, align 8, !tbaa !41
  %29 = getelementptr i8, ptr %28, i64 -24
  %30 = load i64, ptr %29, align 8
  %31 = getelementptr inbounds i8, ptr %0, i64 %30
  invoke void @_ZNSt6__ndk18ios_base8setstateB7v170000Ej(ptr noundef nonnull align 8 dereferenceable(136) %31, i32 noundef 5) #25
          to label %38 unwind label %34

32:                                               ; preds = %3
  %33 = landingpad { ptr, i32 }
          catch ptr null
  br label %41

34:                                               ; preds = %27
  %35 = landingpad { ptr, i32 }
          catch ptr null
  br label %39

36:                                               ; preds = %18, %8
  %37 = landingpad { ptr, i32 }
          catch ptr null
  br label %39

38:                                               ; preds = %27, %25, %5
  call void @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev(ptr noundef nonnull align 8 dereferenceable(16) %4) #24
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %4) #27
  br label %50

39:                                               ; preds = %36, %34
  %40 = phi { ptr, i32 } [ %35, %34 ], [ %37, %36 ]
  call void @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev(ptr noundef nonnull align 8 dereferenceable(16) %4) #24
  br label %41

41:                                               ; preds = %39, %32
  %42 = phi { ptr, i32 } [ %40, %39 ], [ %33, %32 ]
  %43 = extractvalue { ptr, i32 } %42, 0
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %4) #27
  %44 = call ptr @__cxa_begin_catch(ptr %43) #27
  %45 = load ptr, ptr %0, align 8, !tbaa !41
  %46 = getelementptr i8, ptr %45, i64 -24
  %47 = load i64, ptr %46, align 8
  %48 = getelementptr inbounds i8, ptr %0, i64 %47
  invoke void @_ZNSt6__ndk18ios_base33__set_badbit_and_consider_rethrowEv(ptr noundef nonnull align 8 dereferenceable(136) %48) #25
          to label %49 unwind label %51

49:                                               ; preds = %41
  call void @__cxa_end_catch()
  br label %50

50:                                               ; preds = %49, %38
  ret ptr %0

51:                                               ; preds = %41
  %52 = landingpad { ptr, i32 }
          cleanup
  invoke void @__cxa_end_catch()
          to label %53 unwind label %54

53:                                               ; preds = %51
  resume { ptr, i32 } %52

54:                                               ; preds = %51
  %55 = landingpad { ptr, i32 }
          catch ptr null
  %56 = extractvalue { ptr, i32 } %55, 0
  call void @__clang_call_terminate(ptr %56) #28
  unreachable
}

; Function Attrs: minsize optsize
declare void @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_(ptr noundef nonnull align 8 dereferenceable(16), ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #8

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden i64 @_ZNSt6__ndk116__pad_and_outputB7v170000IcNS_11char_traitsIcEEEENS_19ostreambuf_iteratorIT_T0_EES6_PKS4_S8_S8_RNS_8ios_baseES4_(i64 %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, ptr noundef nonnull align 8 dereferenceable(136) %4, i8 noundef %5) local_unnamed_addr #1 comdat personality ptr @__gxx_personality_v0 {
  %7 = alloca %"class.std::__ndk1::basic_string", align 8
  %8 = inttoptr i64 %0 to ptr
  %9 = icmp eq i64 %0, 0
  br i1 %9, label %56, label %10

10:                                               ; preds = %6
  %11 = ptrtoint ptr %3 to i64
  %12 = ptrtoint ptr %1 to i64
  %13 = sub i64 %11, %12
  %14 = getelementptr inbounds %"class.std::__ndk1::ios_base", ptr %4, i64 0, i32 3
  %15 = load i64, ptr %14, align 8, !tbaa !116
  %16 = icmp sgt i64 %15, %13
  %17 = sub nsw i64 %15, %13
  %18 = select i1 %16, i64 %17, i64 0
  %19 = ptrtoint ptr %2 to i64
  %20 = sub i64 %19, %12
  %21 = icmp sgt i64 %20, 0
  br i1 %21, label %22, label %28

22:                                               ; preds = %10
  %23 = load ptr, ptr %8, align 8, !tbaa !41
  %24 = getelementptr inbounds ptr, ptr %23, i64 12
  %25 = load ptr, ptr %24, align 8
  %26 = tail call noundef i64 %25(ptr noundef nonnull align 8 dereferenceable(64) %8, ptr noundef %1, i64 noundef %20) #25
  %27 = icmp eq i64 %26, %20
  br i1 %27, label %28, label %56

28:                                               ; preds = %22, %10
  %29 = icmp sgt i64 %18, 0
  br i1 %29, label %30, label %46

30:                                               ; preds = %28
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %7) #27
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEmc(ptr noundef nonnull align 8 dereferenceable(24) %7, i64 noundef %18, i8 noundef %5) #25
  %31 = load i8, ptr %7, align 8
  %32 = and i8 %31, 1
  %33 = icmp eq i8 %32, 0
  %34 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %7, i64 0, i32 2
  %35 = load ptr, ptr %34, align 8
  %36 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__short", ptr %7, i64 0, i32 2
  %37 = select i1 %33, ptr %36, ptr %35
  %38 = load ptr, ptr %8, align 8, !tbaa !41
  %39 = getelementptr inbounds ptr, ptr %38, i64 12
  %40 = load ptr, ptr %39, align 8
  %41 = invoke noundef i64 %40(ptr noundef nonnull align 8 dereferenceable(64) %8, ptr noundef %37, i64 noundef %18) #25
          to label %42 unwind label %44

42:                                               ; preds = %30
  %43 = icmp eq i64 %41, %18
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %7) #24
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %7) #27
  br i1 %43, label %46, label %56

44:                                               ; preds = %30
  %45 = landingpad { ptr, i32 }
          cleanup
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %7) #24
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %7) #27
  resume { ptr, i32 } %45

46:                                               ; preds = %42, %28
  %47 = sub i64 %11, %19
  %48 = icmp sgt i64 %47, 0
  br i1 %48, label %49, label %55

49:                                               ; preds = %46
  %50 = load ptr, ptr %8, align 8, !tbaa !41
  %51 = getelementptr inbounds ptr, ptr %50, i64 12
  %52 = load ptr, ptr %51, align 8
  %53 = call noundef i64 %52(ptr noundef nonnull align 8 dereferenceable(64) %8, ptr noundef %2, i64 noundef %47) #25
  %54 = icmp eq i64 %53, %47
  br i1 %54, label %55, label %56

55:                                               ; preds = %49, %46
  store i64 0, ptr %14, align 8, !tbaa !116
  br label %56

56:                                               ; preds = %55, %49, %42, %22, %6
  %57 = phi i64 [ 0, %6 ], [ %0, %55 ], [ 0, %42 ], [ 0, %22 ], [ 0, %49 ]
  ret i64 %57
}

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i8 @_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE4fillB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(148) %0) local_unnamed_addr #22 comdat align 2 {
  %2 = getelementptr inbounds %"class.std::__ndk1::basic_ios", ptr %0, i64 0, i32 2
  %3 = load i32, ptr %2, align 8, !tbaa !117
  %4 = icmp eq i32 %3, -1
  br i1 %4, label %5, label %8

5:                                                ; preds = %1
  %6 = tail call noundef i8 @_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE5widenB7v170000Ec(ptr noundef nonnull align 8 dereferenceable(148) %0, i8 noundef 32) #25
  %7 = zext i8 %6 to i32
  store i32 %7, ptr %2, align 8, !tbaa !117
  br label %8

8:                                                ; preds = %5, %1
  %9 = phi i32 [ %7, %5 ], [ %3, %1 ]
  %10 = trunc i32 %9 to i8
  ret i8 %10
}

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev(ptr noundef nonnull align 8 dereferenceable(16)) unnamed_addr #13

; Function Attrs: minsize optsize
declare void @_ZNSt6__ndk18ios_base33__set_badbit_and_consider_rethrowEv(ptr noundef nonnull align 8 dereferenceable(136)) local_unnamed_addr #8

declare void @__cxa_end_catch() local_unnamed_addr

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define available_externally void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEmc(ptr noundef nonnull align 8 dereferenceable(24) %0, i64 noundef %1, i8 noundef %2) local_unnamed_addr #22 align 2 personality ptr @__gxx_personality_v0 {
  %4 = icmp ugt i64 %1, -17
  br i1 %4, label %5, label %6

5:                                                ; preds = %3
  tail call void @_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #31
  unreachable

6:                                                ; preds = %3
  %7 = icmp ult i64 %1, 23
  br i1 %7, label %8, label %12

8:                                                ; preds = %6
  %9 = trunc i64 %1 to i8
  %10 = shl nuw nsw i8 %9, 1
  store i8 %10, ptr %0, align 8
  %11 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__short", ptr %0, i64 0, i32 2
  br label %22

12:                                               ; preds = %6
  %13 = or i64 %1, 15
  %14 = add i64 %13, 1
  %15 = tail call [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIcEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %14) #25
  %16 = extractvalue [2 x i64] %15, 0
  %17 = inttoptr i64 %16 to ptr
  %18 = extractvalue [2 x i64] %15, 1
  %19 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 2
  store ptr %17, ptr %19, align 8, !tbaa !12
  %20 = or i64 %18, 1
  store i64 %20, ptr %0, align 8
  %21 = getelementptr inbounds %"struct.std::__ndk1::basic_string<char>::__long", ptr %0, i64 0, i32 1
  store i64 %1, ptr %21, align 8, !tbaa !12
  br label %22

22:                                               ; preds = %12, %8
  %23 = phi ptr [ %11, %8 ], [ %17, %12 ]
  br label %24

24:                                               ; preds = %28, %22
  %25 = phi i64 [ %1, %22 ], [ %30, %28 ]
  %26 = phi ptr [ %23, %22 ], [ %29, %28 ]
  %27 = icmp eq i64 %25, 0
  br i1 %27, label %31, label %28

28:                                               ; preds = %24
  store i8 %2, ptr %26, align 1, !tbaa !12
  %29 = getelementptr inbounds i8, ptr %26, i64 1
  %30 = add i64 %25, -1
  br label %24, !llvm.loop !119

31:                                               ; preds = %24
  %32 = getelementptr inbounds i8, ptr %23, i64 %1
  store i8 0, ptr %32, align 1, !tbaa !12
  ret void
}

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i8 @_ZNKSt6__ndk19basic_iosIcNS_11char_traitsIcEEE5widenB7v170000Ec(ptr noundef nonnull align 8 dereferenceable(148) %0, i8 noundef %1) local_unnamed_addr #22 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = alloca %"class.std::__ndk1::locale", align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %3) #27
  call void @_ZNKSt6__ndk18ios_base6getlocEv(ptr nonnull sret(%"class.std::__ndk1::locale") align 8 %3, ptr noundef nonnull align 8 dereferenceable(136) %0) #25
  %4 = invoke noundef nonnull align 8 dereferenceable(25) ptr @_ZNSt6__ndk19use_facetB7v170000INS_5ctypeIcEEEERKT_RKNS_6localeE(ptr noundef nonnull align 8 dereferenceable(8) %3) #25
          to label %5 unwind label %11

5:                                                ; preds = %2
  %6 = load ptr, ptr %4, align 8, !tbaa !41
  %7 = getelementptr inbounds ptr, ptr %6, i64 7
  %8 = load ptr, ptr %7, align 8
  %9 = invoke noundef i8 %8(ptr noundef nonnull align 8 dereferenceable(25) %4, i8 noundef %1) #25
          to label %10 unwind label %11

10:                                               ; preds = %5
  call void @_ZNSt6__ndk16localeD1Ev(ptr noundef nonnull align 8 dereferenceable(8) %3) #24
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %3) #27
  ret i8 %9

11:                                               ; preds = %5, %2
  %12 = landingpad { ptr, i32 }
          cleanup
  call void @_ZNSt6__ndk16localeD1Ev(ptr noundef nonnull align 8 dereferenceable(8) %3) #24
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %3) #27
  resume { ptr, i32 } %12
}

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef nonnull align 8 dereferenceable(25) ptr @_ZNSt6__ndk19use_facetB7v170000INS_5ctypeIcEEEERKT_RKNS_6localeE(ptr noundef nonnull align 8 dereferenceable(8) %0) local_unnamed_addr #22 comdat {
  %2 = tail call noundef ptr @_ZNKSt6__ndk16locale9use_facetERNS0_2idE(ptr noundef nonnull align 8 dereferenceable(8) %0, ptr noundef nonnull align 8 dereferenceable(12) @_ZNSt6__ndk15ctypeIcE2idE) #25
  ret ptr %2
}

; Function Attrs: minsize optsize
declare void @_ZNKSt6__ndk18ios_base6getlocEv(ptr sret(%"class.std::__ndk1::locale") align 8, ptr noundef nonnull align 8 dereferenceable(136)) local_unnamed_addr #8

; Function Attrs: minsize nounwind optsize
declare void @_ZNSt6__ndk16localeD1Ev(ptr noundef nonnull align 8 dereferenceable(8)) unnamed_addr #13

; Function Attrs: minsize optsize
declare noundef ptr @_ZNKSt6__ndk16locale9use_facetERNS0_2idE(ptr noundef nonnull align 8 dereferenceable(8), ptr noundef nonnull align 8 dereferenceable(12)) local_unnamed_addr #8

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk18ios_base8setstateB7v170000Ej(ptr noundef nonnull align 8 dereferenceable(136) %0, i32 noundef %1) local_unnamed_addr #22 comdat align 2 {
  %3 = getelementptr inbounds %"class.std::__ndk1::ios_base", ptr %0, i64 0, i32 4
  %4 = load i32, ptr %3, align 8, !tbaa !120
  %5 = or i32 %4, %1
  tail call void @_ZNSt6__ndk18ios_base5clearEj(ptr noundef nonnull align 8 dereferenceable(136) %0, i32 noundef %5) #25
  ret void
}

; Function Attrs: minsize optsize
declare void @_ZNSt6__ndk18ios_base5clearEj(ptr noundef nonnull align 8 dereferenceable(136), i32 noundef) local_unnamed_addr #8

; Function Attrs: minsize optsize
declare noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE3putEc(ptr noundef nonnull align 8 dereferenceable(8), i8 noundef) local_unnamed_addr #8

; Function Attrs: minsize optsize
declare noundef nonnull align 8 dereferenceable(8) ptr @_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE5flushEv(ptr noundef nonnull align 8 dereferenceable(8)) local_unnamed_addr #8

; Function Attrs: minsize nounwind optsize
declare void @_ZN6asmjit5v1_163a649AssemblerC1EPNS0_10CodeHolderE(ptr noundef nonnull align 8 dereferenceable(176), ptr noundef) unnamed_addr #13

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE2icERKNS0_3ImmERKNS1_2GpE(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef nonnull align 4 dereferenceable(16) %1, ptr noundef nonnull align 4 dereferenceable(16) %2) local_unnamed_addr #22 comdat align 2 !type !121 {
  %4 = tail call noundef i32 @_ZN6asmjit5v1_1611BaseEmitter6_emitIEjRKNS0_8Operand_ES4_(ptr noundef nonnull align 8 dereferenceable(144) %0, i32 noundef 101, ptr noundef nonnull align 4 dereferenceable(16) %1, ptr noundef nonnull align 4 dereferenceable(16) %2) #25
  ret i32 %4
}

; Function Attrs: minsize optsize
declare noundef i32 @_ZN6asmjit5v1_1611BaseEmitter6_emitIEjRKNS0_8Operand_ES4_(ptr noundef nonnull align 8 dereferenceable(144), i32 noundef, ptr noundef nonnull align 4 dereferenceable(16), ptr noundef nonnull align 4 dereferenceable(16)) local_unnamed_addr #8

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3dsbERKNS0_3ImmE(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef nonnull align 4 dereferenceable(16) %1) local_unnamed_addr #22 comdat align 2 !type !122 {
  %3 = tail call noundef i32 @_ZN6asmjit5v1_1611BaseEmitter6_emitIEjRKNS0_8Operand_E(ptr noundef nonnull align 8 dereferenceable(144) %0, i32 noundef 91, ptr noundef nonnull align 4 dereferenceable(16) %1) #25
  ret i32 %3
}

; Function Attrs: minsize optsize
declare noundef i32 @_ZN6asmjit5v1_1611BaseEmitter6_emitIEjRKNS0_8Operand_E(ptr noundef nonnull align 8 dereferenceable(144), i32 noundef, ptr noundef nonnull align 4 dereferenceable(16)) local_unnamed_addr #8

; Function Attrs: inlinehint minsize mustprogress optsize uwtable
define linkonce_odr hidden noundef i32 @_ZN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEE3isbERKNS0_3ImmE(ptr noundef nonnull align 1 dereferenceable(1) %0, ptr noundef nonnull align 4 dereferenceable(16) %1) local_unnamed_addr #22 comdat align 2 !type !122 {
  %3 = tail call noundef i32 @_ZN6asmjit5v1_1611BaseEmitter6_emitIEjRKNS0_8Operand_E(ptr noundef nonnull align 8 dereferenceable(144) %0, i32 noundef 102, ptr noundef nonnull align 4 dereferenceable(16) %1) #25
  ret i32 %3
}

; Function Attrs: minsize optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEEC2IPKhLi0EEET_S7_(ptr noundef nonnull align 8 dereferenceable(24) %0, ptr noundef %1, ptr noundef %2) unnamed_addr #1 comdat align 2 personality ptr @__gxx_personality_v0 {
  %4 = alloca %"struct.std::__ndk1::__exception_guard.49", align 8
  %5 = getelementptr inbounds %"class.std::__ndk1::vector.41", ptr %0, i64 0, i32 1
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(24) %0, i8 0, i64 24, i1 false)
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %4) #27
  store ptr %0, ptr %4, align 8, !tbaa.struct !15, !alias.scope !123
  %6 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard.49", ptr %4, i64 0, i32 1
  store i8 0, ptr %6, align 8, !tbaa !126, !alias.scope !123
  %7 = ptrtoint ptr %2 to i64
  %8 = ptrtoint ptr %1 to i64
  %9 = sub i64 %7, %8
  %10 = icmp eq ptr %2, %1
  br i1 %10, label %17, label %11

11:                                               ; preds = %3
  invoke void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE11__vallocateB7v170000Em(ptr noundef nonnull align 8 dereferenceable(24) %0, i64 noundef %9) #25
          to label %12 unwind label %15

12:                                               ; preds = %11
  %13 = load ptr, ptr %5, align 8, !tbaa !102
  tail call void @llvm.memmove.p0.p0.i64(ptr align 1 %13, ptr align 1 %1, i64 %9, i1 false)
  %14 = getelementptr inbounds i8, ptr %13, i64 %9
  store ptr %14, ptr %5, align 8, !tbaa !102
  br label %17

15:                                               ; preds = %11
  %16 = landingpad { ptr, i32 }
          cleanup
  call void @_ZNSt6__ndk117__exception_guardINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %4) #24
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %4) #27
  resume { ptr, i32 } %16

17:                                               ; preds = %12, %3
  store i8 1, ptr %6, align 8, !tbaa !126
  call void @_ZNSt6__ndk117__exception_guardINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %4) #24
  call void @llvm.lifetime.end.p0(i64 16, ptr nonnull %4) #27
  ret void
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE11__vallocateB7v170000Em(ptr noundef nonnull align 8 dereferenceable(24) %0, i64 noundef %1) local_unnamed_addr #6 comdat align 2 personality ptr @__gxx_personality_v0 {
  %3 = icmp slt i64 %1, 0
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  tail call void @_ZNKSt6__ndk16vectorIhNS_9allocatorIhEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) #31
  unreachable

5:                                                ; preds = %2
  %6 = getelementptr inbounds %"class.std::__ndk1::vector.41", ptr %0, i64 0, i32 2
  %7 = tail call [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIhEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %6, i64 noundef %1) #25
  %8 = extractvalue [2 x i64] %7, 0
  %9 = inttoptr i64 %8 to ptr
  %10 = extractvalue [2 x i64] %7, 1
  store ptr %9, ptr %0, align 8, !tbaa !98
  %11 = getelementptr inbounds %"class.std::__ndk1::vector.41", ptr %0, i64 0, i32 1
  store ptr %9, ptr %11, align 8, !tbaa !102
  %12 = getelementptr inbounds i8, ptr %9, i64 %10
  store ptr %12, ptr %6, align 8, !tbaa !16
  ret void
}

; Function Attrs: minsize nounwind optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk117__exception_guardINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEED2B7v170000Ev(ptr noundef nonnull align 8 dereferenceable(9) %0) unnamed_addr #4 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = getelementptr inbounds %"struct.std::__ndk1::__exception_guard.49", ptr %0, i64 0, i32 1
  %3 = load i8, ptr %2, align 8, !tbaa !126, !range !67, !noundef !68
  %4 = icmp eq i8 %3, 0
  br i1 %4, label %5, label %6

5:                                                ; preds = %1
  invoke void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) #25
          to label %6 unwind label %7

6:                                                ; preds = %5, %1
  ret void

7:                                                ; preds = %5
  %8 = landingpad { ptr, i32 }
          catch ptr null
  %9 = extractvalue { ptr, i32 } %8, 0
  tail call void @__clang_call_terminate(ptr %9) #28
  unreachable
}

; Function Attrs: minsize mustprogress noreturn optsize uwtable
define linkonce_odr hidden void @_ZNKSt6__ndk16vectorIhNS_9allocatorIhEEE20__throw_length_errorB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(24) %0) local_unnamed_addr #11 comdat align 2 {
  tail call void @_ZNSt6__ndk120__throw_length_errorB7v170000EPKc(ptr noundef nonnull @.str.19) #31
  unreachable
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden [2 x i64] @_ZNSt6__ndk119__allocate_at_leastB7v170000INS_9allocatorIhEEEENS_19__allocation_resultINS_16allocator_traitsIT_E7pointerEEERS5_m(ptr noundef nonnull align 1 dereferenceable(1) %0, i64 noundef %1) local_unnamed_addr #6 comdat {
  %3 = tail call noalias noundef nonnull ptr @_Znwm(i64 noundef %1) #30
  %4 = ptrtoint ptr %3 to i64
  %5 = insertvalue [2 x i64] poison, i64 %4, 0
  %6 = insertvalue [2 x i64] %5, i64 %1, 1
  ret [2 x i64] %6
}

; Function Attrs: minsize mustprogress optsize uwtable
define linkonce_odr hidden void @_ZNSt6__ndk16vectorIhNS_9allocatorIhEEE16__destroy_vectorclB7v170000Ev(ptr noundef nonnull align 8 dereferenceable(8) %0) local_unnamed_addr #6 comdat align 2 personality ptr @__gxx_personality_v0 {
  %2 = load ptr, ptr %0, align 8, !tbaa !129
  %3 = load ptr, ptr %2, align 8, !tbaa !98
  %4 = icmp eq ptr %3, null
  br i1 %4, label %7, label %5

5:                                                ; preds = %1
  %6 = getelementptr inbounds %"class.std::__ndk1::vector.41", ptr %2, i64 0, i32 1
  store ptr %3, ptr %6, align 8, !tbaa !102
  tail call void @_ZdlPv(ptr noundef nonnull %3) #26
  br label %7

7:                                                ; preds = %5, %1
  ret void
}

; Function Attrs: minsize optsize
declare noundef i64 @_ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm(ptr noundef, i32 noundef, ptr noundef nonnull align 8 dereferenceable(8)) local_unnamed_addr #8

; Function Attrs: minsize optsize uwtable
define internal void @_GLOBAL__sub_I_module_base_cpu_icache_sync.cpp() #1 section ".text.startup" personality ptr @__gxx_personality_v0 {
  %1 = alloca [3 x %"class.std::__ndk1::basic_string"], align 8
  %2 = alloca [5 x %"class.std::__ndk1::basic_string"], align 8
  %3 = alloca [5 x %"class.std::__ndk1::basic_string"], align 8
  call void @llvm.lifetime.start.p0(i64 120, ptr nonnull %3) #27
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %3, ptr noundef nonnull @.str) #25
  %4 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 1
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %4, ptr noundef nonnull @.str.1) #25
          to label %5 unwind label %21

5:                                                ; preds = %0
  %6 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 2
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %6, ptr noundef nonnull @.str.2) #25
          to label %7 unwind label %21

7:                                                ; preds = %5
  %8 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 3
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %8, ptr noundef nonnull @.str.3) #25
          to label %9 unwind label %21

9:                                                ; preds = %7
  %10 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 4
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %10, ptr noundef nonnull @.str.4) #25
          to label %11 unwind label %21

11:                                               ; preds = %9
  %12 = ptrtoint ptr %3 to i64
  %13 = insertvalue [2 x i64] poison, i64 %12, 0
  %14 = insertvalue [2 x i64] %13, i64 5, 1
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEC2B7v170000ESt16initializer_listIS6_E(ptr noundef nonnull align 8 dereferenceable(24) @_ZN13kernel_module13export_symbolL27copy_from_user_symbol_namesE, [2 x i64] %14) #25
          to label %15 unwind label %28

15:                                               ; preds = %11
  %16 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 5
  br label %17

17:                                               ; preds = %17, %15
  %18 = phi ptr [ %16, %15 ], [ %19, %17 ]
  %19 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %18, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %19) #24
  %20 = icmp eq ptr %19, %3
  br i1 %20, label %39, label %17

21:                                               ; preds = %9, %7, %5, %0
  %22 = phi ptr [ %10, %9 ], [ %8, %7 ], [ %6, %5 ], [ %4, %0 ]
  %23 = landingpad { ptr, i32 }
          cleanup
  br label %24

24:                                               ; preds = %24, %21
  %25 = phi ptr [ %22, %21 ], [ %26, %24 ]
  %26 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %25, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %26) #24
  %27 = icmp eq ptr %26, %3
  br i1 %27, label %37, label %24

28:                                               ; preds = %11
  %29 = landingpad { ptr, i32 }
          cleanup
  %30 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %3, i64 5
  br label %31

31:                                               ; preds = %31, %28
  %32 = phi ptr [ %30, %28 ], [ %33, %31 ]
  %33 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %32, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %33) #24
  %34 = icmp eq ptr %33, %3
  br i1 %34, label %37, label %31

35:                                               ; preds = %103, %72, %37
  %36 = phi { ptr, i32 } [ %38, %37 ], [ %73, %72 ], [ %104, %103 ]
  resume { ptr, i32 } %36

37:                                               ; preds = %31, %24
  %38 = phi { ptr, i32 } [ %29, %31 ], [ %23, %24 ]
  call void @llvm.lifetime.end.p0(i64 120, ptr nonnull %3) #27
  br label %35

39:                                               ; preds = %17
  call void @llvm.lifetime.end.p0(i64 120, ptr nonnull %3) #27
  %40 = call i32 @__cxa_atexit(ptr nonnull @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2B7v170000Ev, ptr nonnull @_ZN13kernel_module13export_symbolL27copy_from_user_symbol_namesE, ptr nonnull @__dso_handle) #27
  call void @llvm.lifetime.start.p0(i64 120, ptr nonnull %2) #27
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %2, ptr noundef nonnull @.str.6) #25
  %41 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 1
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %41, ptr noundef nonnull @.str.7) #25
          to label %42 unwind label %58

42:                                               ; preds = %39
  %43 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 2
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %43, ptr noundef nonnull @.str.8) #25
          to label %44 unwind label %58

44:                                               ; preds = %42
  %45 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 3
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %45, ptr noundef nonnull @.str.9) #25
          to label %46 unwind label %58

46:                                               ; preds = %44
  %47 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 4
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %47, ptr noundef nonnull @.str.10) #25
          to label %48 unwind label %58

48:                                               ; preds = %46
  %49 = ptrtoint ptr %2 to i64
  %50 = insertvalue [2 x i64] poison, i64 %49, 0
  %51 = insertvalue [2 x i64] %50, i64 5, 1
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEC2B7v170000ESt16initializer_listIS6_E(ptr noundef nonnull align 8 dereferenceable(24) @_ZN13kernel_module13export_symbolL25copy_to_user_symbol_namesE, [2 x i64] %51) #25
          to label %52 unwind label %65

52:                                               ; preds = %48
  %53 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 5
  br label %54

54:                                               ; preds = %54, %52
  %55 = phi ptr [ %53, %52 ], [ %56, %54 ]
  %56 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %55, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %56) #24
  %57 = icmp eq ptr %56, %2
  br i1 %57, label %74, label %54

58:                                               ; preds = %46, %44, %42, %39
  %59 = phi ptr [ %47, %46 ], [ %45, %44 ], [ %43, %42 ], [ %41, %39 ]
  %60 = landingpad { ptr, i32 }
          cleanup
  br label %61

61:                                               ; preds = %61, %58
  %62 = phi ptr [ %59, %58 ], [ %63, %61 ]
  %63 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %62, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %63) #24
  %64 = icmp eq ptr %63, %2
  br i1 %64, label %72, label %61

65:                                               ; preds = %48
  %66 = landingpad { ptr, i32 }
          cleanup
  %67 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %2, i64 5
  br label %68

68:                                               ; preds = %68, %65
  %69 = phi ptr [ %67, %65 ], [ %70, %68 ]
  %70 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %69, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %70) #24
  %71 = icmp eq ptr %70, %2
  br i1 %71, label %72, label %68

72:                                               ; preds = %68, %61
  %73 = phi { ptr, i32 } [ %66, %68 ], [ %60, %61 ]
  call void @llvm.lifetime.end.p0(i64 120, ptr nonnull %2) #27
  br label %35

74:                                               ; preds = %54
  call void @llvm.lifetime.end.p0(i64 120, ptr nonnull %2) #27
  %75 = call i32 @__cxa_atexit(ptr nonnull @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2B7v170000Ev, ptr nonnull @_ZN13kernel_module13export_symbolL25copy_to_user_symbol_namesE, ptr nonnull @__dso_handle) #27
  call void @llvm.lifetime.start.p0(i64 72, ptr nonnull %1) #27
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %1, ptr noundef nonnull @.str.12) #25
  %76 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %1, i64 1
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %76, ptr noundef nonnull @.str.13) #25
          to label %77 unwind label %89

77:                                               ; preds = %74
  %78 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %1, i64 2
  invoke void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2B7v170000IDnEEPKc(ptr noundef nonnull align 8 dereferenceable(24) %78, ptr noundef nonnull @.str.14) #25
          to label %79 unwind label %89

79:                                               ; preds = %77
  %80 = ptrtoint ptr %1 to i64
  %81 = insertvalue [2 x i64] poison, i64 %80, 0
  %82 = insertvalue [2 x i64] %81, i64 3, 1
  invoke void @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEC2B7v170000ESt16initializer_listIS6_E(ptr noundef nonnull align 8 dereferenceable(24) @_ZN13kernel_module13export_symbolL37copy_from_kernel_nofault_symbol_namesE, [2 x i64] %82) #25
          to label %83 unwind label %96

83:                                               ; preds = %79
  %84 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %1, i64 3
  br label %85

85:                                               ; preds = %85, %83
  %86 = phi ptr [ %84, %83 ], [ %87, %85 ]
  %87 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %86, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %87) #24
  %88 = icmp eq ptr %87, %1
  br i1 %88, label %105, label %85

89:                                               ; preds = %77, %74
  %90 = phi ptr [ %78, %77 ], [ %76, %74 ]
  %91 = landingpad { ptr, i32 }
          cleanup
  br label %92

92:                                               ; preds = %92, %89
  %93 = phi ptr [ %90, %89 ], [ %94, %92 ]
  %94 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %93, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %94) #24
  %95 = icmp eq ptr %94, %1
  br i1 %95, label %103, label %92

96:                                               ; preds = %79
  %97 = landingpad { ptr, i32 }
          cleanup
  %98 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %1, i64 3
  br label %99

99:                                               ; preds = %99, %96
  %100 = phi ptr [ %98, %96 ], [ %101, %99 ]
  %101 = getelementptr inbounds %"class.std::__ndk1::basic_string", ptr %100, i64 -1
  call void @_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev(ptr noundef nonnull align 8 dereferenceable(24) %101) #24
  %102 = icmp eq ptr %101, %1
  br i1 %102, label %103, label %99

103:                                              ; preds = %99, %92
  %104 = phi { ptr, i32 } [ %97, %99 ], [ %91, %92 ]
  call void @llvm.lifetime.end.p0(i64 72, ptr nonnull %1) #27
  br label %35

105:                                              ; preds = %85
  call void @llvm.lifetime.end.p0(i64 72, ptr nonnull %1) #27
  %106 = call i32 @__cxa_atexit(ptr nonnull @_ZNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2B7v170000Ev, ptr nonnull @_ZN13kernel_module13export_symbolL37copy_from_kernel_nofault_symbol_namesE, ptr nonnull @__dso_handle) #27
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite)
declare void @llvm.experimental.noalias.scope.decl(metadata) #10

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i32 @llvm.smax.i32(i32, i32) #23

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #1 = { minsize optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #2 = { inlinehint minsize nounwind optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #3 = { inlinehint minsize optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #4 = { minsize nounwind optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #5 = { nofree nounwind }
attributes #6 = { minsize mustprogress optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #7 = { minsize nofree nounwind optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #8 = { minsize optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #9 = { minsize mustprogress nofree nosync nounwind optsize willreturn memory(none) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #10 = { nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite) }
attributes #11 = { minsize mustprogress noreturn optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #12 = { inlinehint minsize mustprogress noreturn optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #13 = { minsize nounwind optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #14 = { minsize nobuiltin optsize allocsize(0) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #15 = { minsize noinline noreturn nounwind optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #16 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #17 = { minsize mustprogress nofree nounwind optsize willreturn memory(argmem: read) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #18 = { minsize nobuiltin nounwind optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #19 = { minsize mustprogress nounwind optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #20 = { minsize nofree optsize "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #21 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #22 = { inlinehint minsize mustprogress optsize uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fix-cortex-a53-835769,+fp-armv8,+neon,+outline-atomics,+v8a" }
attributes #23 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #24 = { minsize nounwind optsize }
attributes #25 = { minsize optsize }
attributes #26 = { builtin minsize nounwind optsize }
attributes #27 = { nounwind }
attributes #28 = { noreturn nounwind }
attributes #29 = { minsize nounwind optsize willreturn memory(none) }
attributes #30 = { builtin minsize optsize allocsize(0) }
attributes #31 = { minsize noreturn optsize }
attributes #32 = { noreturn }

!llvm.linker.options = !{}
!llvm.module.flags = !{!6, !7, !8, !9, !10}
!llvm.ident = !{!11}

!0 = !{i64 16, !1}
!1 = distinct !{}
!2 = !{i64 32, !3}
!3 = distinct !{}
!4 = !{i64 16, !"_ZTSN6asmjit5v1_1612ErrorHandlerE"}
!5 = !{i64 32, !"_ZTSMN6asmjit5v1_1612ErrorHandlerEFvjPKcPNS0_11BaseEmitterEE.virtual"}
!6 = !{i32 1, !"wchar_size", i32 4}
!7 = !{i32 8, !"PIC Level", i32 2}
!8 = !{i32 7, !"uwtable", i32 2}
!9 = !{i32 7, !"frame-pointer", i32 1}
!10 = !{i32 1, !"EnableSplitLTOUnit", i32 0}
!11 = !{!"Android (11349228, based on r487747e) clang version 17.0.2 (https://android.googlesource.com/toolchain/llvm-project d9f89f4d16663d5012e5c09495f3b30ece3d2362)"}
!12 = !{!13, !13, i64 0}
!13 = !{!"omnipotent char", !14, i64 0}
!14 = !{!"Simple C++ TBAA"}
!15 = !{i64 0, i64 8, !16}
!16 = !{!17, !17, i64 0}
!17 = !{!"any pointer", !13, i64 0}
!18 = !{!19}
!19 = distinct !{!19, !20, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEEENS_17__exception_guardIT_EESC_: argument 0"}
!20 = distinct !{!20, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEEENS_17__exception_guardIT_EESC_"}
!21 = !{!22, !24, i64 8}
!22 = !{!"_ZTSNSt6__ndk117__exception_guardINS_6vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS5_IS7_EEE16__destroy_vectorEEE", !23, i64 0, !24, i64 8}
!23 = !{!"_ZTSNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE16__destroy_vectorE", !17, i64 0}
!24 = !{!"bool", !13, i64 0}
!25 = !{!26, !26, i64 0}
!26 = !{!"_ZTS7KModErr", !13, i64 0}
!27 = !{!28, !28, i64 0}
!28 = !{!"int", !13, i64 0}
!29 = !{!30}
!30 = distinct !{!30, !31, !"_ZN12_GLOBAL__N_116init_aarch64_asmEv: argument 0"}
!31 = distinct !{!31, !"_ZN12_GLOBAL__N_116init_aarch64_asmEv"}
!32 = !{!33, !34, i64 0}
!33 = !{!"_ZTSN6asmjit5v1_1611EnvironmentE", !34, i64 0, !35, i64 1, !36, i64 2, !37, i64 3, !38, i64 4, !39, i64 5, !40, i64 6, !13, i64 7}
!34 = !{!"_ZTSN6asmjit5v1_164ArchE", !13, i64 0}
!35 = !{!"_ZTSN6asmjit5v1_167SubArchE", !13, i64 0}
!36 = !{!"_ZTSN6asmjit5v1_166VendorE", !13, i64 0}
!37 = !{!"_ZTSN6asmjit5v1_168PlatformE", !13, i64 0}
!38 = !{!"_ZTSN6asmjit5v1_1611PlatformABIE", !13, i64 0}
!39 = !{!"_ZTSN6asmjit5v1_1612ObjectFormatE", !13, i64 0}
!40 = !{!"_ZTSN6asmjit5v1_168FloatABIE", !13, i64 0}
!41 = !{!42, !42, i64 0}
!42 = !{!"vtable pointer", !14, i64 0}
!43 = !{!44}
!44 = distinct !{!44, !45, !"_ZNSt6__ndk111make_uniqueB7v170000IN12_GLOBAL__N_120MyAsmJitErrorHandlerEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_: argument 0"}
!45 = distinct !{!45, !"_ZNSt6__ndk111make_uniqueB7v170000IN12_GLOBAL__N_120MyAsmJitErrorHandlerEJEEENS_11__unique_ifIT_E15__unique_singleEDpOT0_"}
!46 = !{!47, !24, i64 8}
!47 = !{!"_ZTSN12_GLOBAL__N_120MyAsmJitErrorHandlerE", !48, i64 0, !24, i64 8}
!48 = !{!"_ZTSN6asmjit5v1_1612ErrorHandlerE"}
!49 = !{!50, !28, i64 0}
!50 = !{!"_ZTSN6asmjit5v1_1616OperandSignatureE", !28, i64 0}
!51 = !{!52, !28, i64 4}
!52 = !{!"_ZTSN6asmjit5v1_168Operand_E", !50, i64 0, !28, i64 4, !13, i64 8}
!53 = !{!54}
!54 = distinct !{!54, !55, !"_ZN12_GLOBAL__N_120aarch64_asm_to_bytesEPKN6asmjit5v1_163a649AssemblerE: argument 0"}
!55 = distinct !{!55, !"_ZN12_GLOBAL__N_120aarch64_asm_to_bytesEPKN6asmjit5v1_163a649AssemblerE"}
!56 = !{!57, !17, i64 64}
!57 = !{!"_ZTSN6asmjit5v1_1611BaseEmitterE", !58, i64 8, !59, i64 9, !13, i64 10, !13, i64 11, !60, i64 12, !61, i64 16, !62, i64 24, !63, i64 32, !64, i64 36, !28, i64 40, !17, i64 48, !17, i64 56, !17, i64 64, !33, i64 72, !50, i64 80, !64, i64 84, !65, i64 88, !17, i64 96, !66, i64 104}
!58 = !{!"_ZTSN6asmjit5v1_1611EmitterTypeE", !13, i64 0}
!59 = !{!"_ZTSN6asmjit5v1_1612EmitterFlagsE", !13, i64 0}
!60 = !{!"_ZTSN6asmjit5v1_1615ValidationFlagsE", !13, i64 0}
!61 = !{!"_ZTSN6asmjit5v1_1617DiagnosticOptionsE", !13, i64 0}
!62 = !{!"long", !13, i64 0}
!63 = !{!"_ZTSN6asmjit5v1_1615EncodingOptionsE", !13, i64 0}
!64 = !{!"_ZTSN6asmjit5v1_1611InstOptionsE", !13, i64 0}
!65 = !{!"_ZTSN6asmjit5v1_167RegOnlyE", !50, i64 0, !28, i64 4}
!66 = !{!"_ZTSN6asmjit5v1_1611BaseEmitter5FuncsE", !17, i64 0, !17, i64 8, !17, i64 16, !17, i64 24, !17, i64 32}
!67 = !{i8 0, i8 2}
!68 = !{}
!69 = !{!57, !17, i64 48}
!70 = !{!71, !17, i64 0}
!71 = !{!"_ZTSN6asmjit5v1_1614ZoneVectorBaseE", !17, i64 0, !28, i64 8, !28, i64 12}
!72 = !{!73, !17, i64 0}
!73 = !{!"_ZTSN6asmjit5v1_1610CodeBufferE", !17, i64 0, !62, i64 8, !62, i64 16, !74, i64 24}
!74 = !{!"_ZTSN6asmjit5v1_1615CodeBufferFlagsE", !13, i64 0}
!75 = !{!73, !62, i64 8}
!76 = !{!62, !62, i64 0}
!77 = distinct !{!77, !78}
!78 = !{!"llvm.loop.mustprogress"}
!79 = !{!80, !17, i64 0}
!80 = !{!"_ZTSNSt6__ndk16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEE", !17, i64 0, !17, i64 8, !81, i64 16}
!81 = !{!"_ZTSNSt6__ndk117__compressed_pairIPNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEE", !82, i64 0}
!82 = !{!"_ZTSNSt6__ndk122__compressed_pair_elemIPNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEELi0ELb0EEE", !17, i64 0}
!83 = !{!80, !17, i64 8}
!84 = !{!85, !24, i64 24}
!85 = !{!"_ZTSNSt6__ndk117__exception_guardINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEEE", !86, i64 0, !24, i64 24}
!86 = !{!"_ZTSNSt6__ndk129_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPS6_EE", !17, i64 0, !17, i64 8, !17, i64 16}
!87 = !{!88}
!88 = distinct !{!88, !89, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEEENS_17__exception_guardIT_EESC_: argument 0"}
!89 = distinct !{!89, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS2_IcEEEEEEPS7_EEEENS_17__exception_guardIT_EESC_"}
!90 = distinct !{!90, !78}
!91 = !{i64 0, i64 8, !76, i64 0, i64 8, !76, i64 8, i64 8, !76, i64 16, i64 8, !16, i64 0, i64 1, !12, i64 0, i64 1, !12, i64 1, i64 0, !12, i64 1, i64 23, !12, i64 0, i64 24, !12}
!92 = !{i64 0, !"_ZTSMNSt6__ndk129_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic_stringIcNS_11char_traitsIcEENS1_IcEEEEEEPS6_EEKFvvE"}
!93 = !{!86, !17, i64 0}
!94 = !{!86, !17, i64 16}
!95 = !{!86, !17, i64 8}
!96 = distinct !{!96, !78}
!97 = !{!23, !17, i64 0}
!98 = !{!99, !17, i64 0}
!99 = !{!"_ZTSNSt6__ndk16vectorIhNS_9allocatorIhEEEE", !17, i64 0, !17, i64 8, !100, i64 16}
!100 = !{!"_ZTSNSt6__ndk117__compressed_pairIPhNS_9allocatorIhEEEE", !101, i64 0}
!101 = !{!"_ZTSNSt6__ndk122__compressed_pair_elemIPhLi0ELb0EEE", !17, i64 0}
!102 = !{!99, !17, i64 8}
!103 = !{!104, !17, i64 0}
!104 = !{!"_ZTSNSt6__ndk122__compressed_pair_elemIPN6asmjit5v1_1610CodeHolderELi0ELb0EEE", !17, i64 0}
!105 = !{!106, !17, i64 0}
!106 = !{!"_ZTSNSt6__ndk122__compressed_pair_elemIPN6asmjit5v1_1612StringLoggerELi0ELb0EEE", !17, i64 0}
!107 = !{!108, !17, i64 0}
!108 = !{!"_ZTSNSt6__ndk122__compressed_pair_elemIPN6asmjit5v1_163a649AssemblerELi0ELb0EEE", !17, i64 0}
!109 = !{i64 0, !"_ZTSMNSt6__ndk110unique_ptrIN6asmjit5v1_1610CodeHolderENS_14default_deleteIS3_EEEEDoFvPS3_E"}
!110 = !{i64 0, !"_ZTSMNSt6__ndk114default_deleteIN6asmjit5v1_1610CodeHolderEEEKDoFvPS3_E"}
!111 = !{!112, !24, i64 0}
!112 = !{!"_ZTSNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEE6sentryE", !24, i64 0, !17, i64 8}
!113 = !{!114, !17, i64 40}
!114 = !{!"_ZTSNSt6__ndk18ios_baseE", !28, i64 8, !62, i64 16, !62, i64 24, !28, i64 32, !28, i64 36, !17, i64 40, !17, i64 48, !17, i64 56, !17, i64 64, !62, i64 72, !62, i64 80, !17, i64 88, !62, i64 96, !62, i64 104, !17, i64 112, !62, i64 120, !62, i64 128}
!115 = !{!114, !28, i64 8}
!116 = !{!114, !62, i64 24}
!117 = !{!118, !28, i64 144}
!118 = !{!"_ZTSNSt6__ndk19basic_iosIcNS_11char_traitsIcEEEE", !114, i64 0, !17, i64 136, !28, i64 144}
!119 = distinct !{!119, !78}
!120 = !{!114, !28, i64 32}
!121 = !{i64 0, !"_ZTSMN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEEEFjRKNS0_3ImmERKNS1_2GpEE"}
!122 = !{i64 0, !"_ZTSMN6asmjit5v1_163a6416EmitterExplicitTINS1_9AssemblerEEEFjRKNS0_3ImmEE"}
!123 = !{!124}
!124 = distinct !{!124, !125, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEENS_17__exception_guardIT_EES7_: argument 0"}
!125 = distinct !{!125, !"_ZNSt6__ndk122__make_exception_guardB7v170000INS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEENS_17__exception_guardIT_EES7_"}
!126 = !{!127, !24, i64 8}
!127 = !{!"_ZTSNSt6__ndk117__exception_guardINS_6vectorIhNS_9allocatorIhEEE16__destroy_vectorEEE", !128, i64 0, !24, i64 8}
!128 = !{!"_ZTSNSt6__ndk16vectorIhNS_9allocatorIhEEE16__destroy_vectorE", !17, i64 0}
!129 = !{!128, !17, i64 0}
