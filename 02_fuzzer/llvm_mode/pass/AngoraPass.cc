#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <llvm/Transforms/Utils/Local.h>

#include "./abilist.h"
#include "./defs.h"
#include "./debug.h"

using namespace llvm;
// only do taint tracking, used for compile 3rd libraries.
static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);

static cl::list<std::string> ClABIListFiles(
    "angora-dfsan-abilist",
    cl::desc("file listing native abi functions and how the pass treats them"),
    cl::Hidden);

static cl::list<std::string> ClExploitListFiles(
    "angora-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);

static cl::opt<std::string> CFGFile(
    "cfg-out",
    cl::desc("path to write cfg file to"),
    cl::value_desc("filename"));

//static cl::list<std::string>

namespace {

#define MAX_EXPLOIT_CATEGORY 5
const char *ExploitCategoryAll = "all";
const char *ExploitCategory[] = {"i0", "i1", "i2", "i3", "i4"};
const char *CompareFuncCat = "cmpfn";
const char *SocketReadyCat = "socket";
const char *SourceCat = "source";
const char *SinkCat = "sink";

// hash file name and file size
u32 hashName(std::string str) {
  std::ifstream in(str, std::ifstream::ate | std::ifstream::binary);
  u32 fsize = in.tellg();
  u32 hash = 5381 + fsize * 223;
  for (auto c : str)
    hash = ((hash << 5) + hash) + (unsigned char) c; /* hash * 33 + c */
  return hash;
}

class SinkSourceInfo {
public:
  SinkSourceInfo(Module &M, const AngoraABIList &ExploitList);

  enum SinkSourceState {
    No = -1,
    Unknown = 0,
    Yes = 1,
  };

  SinkSourceState can_reach_sink_before_source(BasicBlock *BB);
  SinkSourceState will_reach_source(BasicBlock *BB);
  SinkSourceState is_sink_before_source(BasicBlock *BB);
  SinkSourceState is_source(BasicBlock *BB);

  SinkSourceState is_sink_before_source(Function *F);
  SinkSourceState is_source(Function *F);

  const std::vector<BasicBlock *> &sources() const;
private:
  const AngoraABIList &ExploitList;

  SinkSourceState _compute_can_reach_sink_before_source(BasicBlock *BB);
  SinkSourceState _compute_will_reach_source(BasicBlock *BB);
  SinkSourceState _compute_is_sink_before_source(BasicBlock *BB);
  SinkSourceState _compute_is_source(BasicBlock *BB);

  SinkSourceState _lookup(BasicBlock *key, const std::map<BasicBlock *, bool> &map);

  std::map<BasicBlock *, bool> is_sink_before_source_map;
  std::map<BasicBlock *, bool> is_source_map;
  std::map<BasicBlock *, bool> can_reach_sink_before_source_map;
  std::map<BasicBlock *, bool> will_reach_source_map;

  void process_scc(const std::vector<CallGraphNode *> &cgns);
  std::vector<BasicBlock *> _sources;

};

class AngoraLLVMPass : public ModulePass {
public:
  static char ID;
  bool FastMode = false;
  std::string ModName;
  u32 ModId;
  unsigned long int RandSeed = 1;
  bool is_bc; // true if inputfile is LLVM bitcode
  unsigned int inst_ratio = 100;
  llvm::ValueMap<const Instruction *, u32> IdMap;

  llvm::ValueMap<const Instruction *, u32> CmpMap; // subset of IdMap for comparison statements (if/branch/etc)

  // Const Variables
  DenseSet<u32> UniqCidSet;

  // Configurations
  bool gen_id_random;
  bool output_cond_loc;
  int num_fn_ctx;

  MDNode *ColdCallWeights;

  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  PointerType *Int8PtrTy;
  PointerType *Int64PtrTy;

  // Global vars
  GlobalVariable *AngoraMapPtr;
  GlobalVariable *AngoraPrevLoc;
  GlobalVariable *AngoraContext;
  GlobalVariable *AngoraCondId;
  GlobalVariable *AngoraCallSite;
  GlobalVariable *ParmeSanIndCallSite;

  FunctionCallee TraceCmp;
  FunctionCallee TraceSw;
  FunctionCallee TraceCmpTT;
  FunctionCallee TraceSwTT;
  FunctionCallee TraceFnTT;
  FunctionCallee TraceExploitTT;
  FunctionCallee ListenReady;
  FunctionCallee CheckTerminate;

  FunctionType *TraceCmpTy;
  FunctionType *TraceSwTy;
  FunctionType *TraceCmpTtTy;
  FunctionType *TraceSwTtTy;
  FunctionType *TraceFnTtTy;
  FunctionType *TraceExploitTtTy;
  FunctionType *ListenReadyTy;
  FunctionType *CheckTerminateTy;

  // Custom setting
  AngoraABIList ABIList;
  AngoraABIList ExploitList;

  // Meta
  unsigned NoSanMetaId;
  MDTuple *NoneMetaNode;
  unsigned InsnIdMetaId;

  AngoraLLVMPass() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomBasicBlockId();
  bool skipBasicBlock();
  u32 getRandomNum();
  void setRandomNumSeed(u32 seed);
  u32 getRandomContextId();
  u32 getRandomInstructionId();
  void setValueNonSan(Value *v);
  void setInsNonSan(Instruction *v);
  Value *castArgType(IRBuilder<> &IRB, Value *V);
  void initVariables(Module &M);
  void countEdge(Module &M, BasicBlock &BB);
  void visitIndirectCallDominator(CallInst *CI, u32 CallSiteId);
  void visitCallInst(Instruction *Inst);
  void visitInvokeInst(Instruction *Inst);
  void visitCompareFunc(Instruction *Inst);
  void visitBranchInst(Instruction *Inst);
  void visitCmpInst(Instruction *Inst);
  void processCmp(Instruction *Cond, Constant *Cid, Instruction *InsertPoint);
  void processBoolCmp(Value *Cond, Constant *Cid, Instruction *InsertPoint);
  void visitSwitchInst(Module &M, Instruction *Inst);
  void visitExploitation(Instruction *Inst);
  void processCall(Instruction *Inst);
  void visitExploitation(CallInst *Inst);
  void addFnWrap(Function &F);
  void collectPreviousIndirectBranch(Instruction *Inst, SmallPtrSet<Instruction *, 16> *);
  void resetIndirectCallContext(IRBuilder<> *IRB);

  void export_cfg();

  void writeTargetsJson(std::basic_ofstream<char> &out, std::set<std::pair<u32, u32>> &edges, std::set<u32> &targets);
  void visitListenCall(Instruction *Inst);
  void add_early_termination(Module &M);

  SinkSourceInfo *SSI;
};

} // namespace

char AngoraLLVMPass::ID = 0;

u32 AngoraLLVMPass::getRandomBasicBlockId() { return random() % MAP_SIZE; }

bool AngoraLLVMPass::skipBasicBlock() { return (random() % 100) >= inst_ratio; }

// http://pubs.opengroup.org/onlinepubs/009695399/functions/rand.html
u32 AngoraLLVMPass::getRandomNum() {
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32) RandSeed;
}

void AngoraLLVMPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

u32 AngoraLLVMPass::getRandomContextId() {
  u32 context = getRandomNum() % MAP_SIZE;
  if (output_cond_loc) {
    errs() << "[CONTEXT] " << context << "\n";
  }
  return context;
}

// We need a consistent cmp ID between fast and track compilations for
// __angora_trace_cmp and __angora_trace_switch,
// other IDs are only used during track runs
// -> let IDPass assign an instruction_id to every instruction, read id from metadata here
u32 AngoraLLVMPass::getInstructionId(Instruction *Inst) {
  u32 h = 0;
  MDNode *isn_id = Inst->getMetadata(InsnIdMetaId);

  if (isn_id != nullptr) {
    if (ConstantAsMetadata *CMD = dyn_cast<ConstantAsMetadata>(isn_id->getOperand(0))) {
      Constant *CV = CMD->getValue();
      if (ConstantInt *CI = dyn_cast<ConstantInt>(CV)) {
        h = CI->getZExtValue();
      }
    }
  }

  if (output_cond_loc) {
    errs() << "[ID] " << h << "\n";
    errs() << "[INS] " << *Inst << "\n";
    if (DILocation *Loc = Inst->getDebugLoc()) {
      errs() << "[LOC] " << cast<DIScope>(Loc->getScope())->getFilename()
             << ", Ln " << Loc->getLine() << ", Col " << Loc->getColumn()
             << "\n";
    }
  }

  // Store mappings
  IdMap[Inst] = h;

  return h;
}

void AngoraLLVMPass::setValueNonSan(Value *v) {
  if (Instruction *ins = dyn_cast<Instruction>(v))
    setInsNonSan(ins);
}

void AngoraLLVMPass::setInsNonSan(Instruction *ins) {
  if (ins)
    ins->setMetadata(NoSanMetaId, NoneMetaNode);
}

void AngoraLLVMPass::initVariables(Module &M) {
  // To ensure different version binaries have the same id
  ModName = M.getModuleIdentifier();
  if (ModName.size() == 0)
    FATAL("No ModName!\n");
  ModId = hashName(ModName);
  errs() << "ModName: " << ModName << " -- " << ModId << "\n";
  is_bc = 0 == ModName.compare(ModName.length() - 3, 3, ".bc");
  if (is_bc) {
    errs() << "Input is LLVM bitcode\n";
  }

  char *inst_ratio_str = getenv("ANGORA_INST_RATIO");
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of ANGORA_INST_RATIO (must be between 1 and 100)");
  }
  errs() << "inst_ratio: " << inst_ratio << "\n";

  // set seed
  srandom(ModId);
  setRandomNumSeed(ModId);

  LLVMContext &C = M.getContext();
  VoidTy = Type::getVoidTy(C);
  Int1Ty = IntegerType::getInt1Ty(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  ColdCallWeights = MDBuilder(C).createBranchWeights(1, 1000);

  NoSanMetaId = C.getMDKindID("nosanitize");
  NoneMetaNode = MDNode::get(C, None);

  InsnIdMetaId = C.getMDKindID("instruction_id");

  AngoraContext =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_context", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  AngoraCallSite = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::CommonLinkage,
      ConstantInt::get(Int32Ty, 0), "__angora_call_site", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  ParmeSanIndCallSite = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::CommonLinkage,
      ConstantInt::get(Int32Ty, 0), "__angora_indirect_call_site", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  ListenReadyTy = FunctionType::get(VoidTy, false);
  ListenReady = M.getOrInsertFunction("__angora_listen_ready", ListenReadyTy);
  if (Function *F = dyn_cast<Function>(ListenReady.getCallee())) {
    F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
  }

  CheckTerminateTy = FunctionType::get(VoidTy, false);
  CheckTerminate = M.getOrInsertFunction("__angora_check_terminate_static", CheckTerminateTy);
  if (Function *F = dyn_cast<Function>(CheckTerminate.getCallee())) {
    F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
  }

  if (FastMode) {
    AngoraMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                      GlobalValue::ExternalLinkage, 0,
                                      "__angora_area_ptr");

    AngoraCondId =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__angora_cond_cmpid");

    AngoraPrevLoc =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                           ConstantInt::get(Int32Ty, 0), "__angora_prev_loc", 0,
                           GlobalVariable::GeneralDynamicTLSModel, 0, false);

    Type *TraceCmpArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty};
    TraceCmpTy = FunctionType::get(Int32Ty, TraceCmpArgs, false);
    TraceCmp = M.getOrInsertFunction("__angora_trace_cmp", TraceCmpTy);
    if (Function *F = dyn_cast<Function>(TraceCmp.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
      // F->addAttribute(1, Attribute::ZExt);
    }

    Type *TraceSwArgs[3] = {Int32Ty, Int32Ty, Int64Ty};
    TraceSwTy = FunctionType::get(Int64Ty, TraceSwArgs, false);
    TraceSw = M.getOrInsertFunction("__angora_trace_switch", TraceSwTy);
    if (Function *F = dyn_cast<Function>(TraceSw.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
      // F->addAttribute(LLVM_ATTRIBUTE_LIST::ReturnIndex, Attribute::ZExt);
      // F->addAttribute(1, Attribute::ZExt);
    }

  } else if (TrackMode) {
    Type *TraceCmpTtArgs[8] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int32Ty,
                               Int64Ty, Int64Ty, Int32Ty};
    TraceCmpTtTy = FunctionType::get(VoidTy, TraceCmpTtArgs, false);
    TraceCmpTT = M.getOrInsertFunction("__angora_trace_cmp_tt", TraceCmpTtTy);
    if (Function *F = dyn_cast<Function>(TraceCmpTT.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }

    Type *TraceSwTtArgs[7] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty,
                              Int64Ty, Int32Ty, Int64PtrTy};
    TraceSwTtTy = FunctionType::get(VoidTy, TraceSwTtArgs, false);
    TraceSwTT = M.getOrInsertFunction("__angora_trace_switch_tt", TraceSwTtTy);
    if (Function *F = dyn_cast<Function>(TraceSwTT.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }

    Type *TraceFnTtArgs[6] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int8PtrTy, Int8PtrTy};
    TraceFnTtTy = FunctionType::get(VoidTy, TraceFnTtArgs, false);
    TraceFnTT = M.getOrInsertFunction("__angora_trace_fn_tt", TraceFnTtTy);
    if (Function *F = dyn_cast<Function>(TraceFnTT.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadOnly); //TODO: Why here ReadOnly instead of ReadNone??
    }

    Type *TraceExploitTtArgs[6] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty};
    TraceExploitTtTy = FunctionType::get(VoidTy, TraceExploitTtArgs, false);
    TraceExploitTT = M.getOrInsertFunction("__angora_trace_exploit_val_tt",
                                           TraceExploitTtTy);
    if (Function *F = dyn_cast<Function>(TraceExploitTT.getCallee())) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      //F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }
  }

  std::vector<std::string> AllABIListFiles;
  AllABIListFiles.insert(AllABIListFiles.end(), ClABIListFiles.begin(),
                         ClABIListFiles.end());
  ABIList.set(SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles, *vfs::getRealFileSystem()));

  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  num_fn_ctx = -1;
  char *custom_fn_ctx = getenv(CUSTOM_FN_CTX);
  if (custom_fn_ctx) {
    num_fn_ctx = atoi(custom_fn_ctx);
    if (num_fn_ctx < 0 || num_fn_ctx >= 32) {
      errs() << "custom context should be: >= 0 && < 32 \n";
      exit(1);
    }
  }

  if (num_fn_ctx == 0) {
    errs() << "disable context\n";
  }

  if (num_fn_ctx > 0) {
    errs() << "use custom function call context: " << num_fn_ctx << "\n";
  }

  if (output_cond_loc) {
    errs() << "Output cond log\n";
  }

  // Pre-processing: find BBs that
  // * call a sink (`is_sink_before_source`)
  // * call a source (`is_source`)
  // * can reach a sink (`can_reach_sink_before_source`)
  // * will always reach a source (`will_reach_source`)
  // TODO: 1. split basic blocks *after* call instructions
  // TODO: 2. make successors of callsites implicit successors of exit blocks of called functions
  // TODO: 3. with both in place: remove the do_not_modify-logic in add_early_termination
  SSI = new SinkSourceInfo(M, ExploitList);

};

// Coverage statistics: AFL's Branch count
// Angora enable function-call context.
void AngoraLLVMPass::countEdge(Module &M, BasicBlock &BB) {
  if (!FastMode || skipBasicBlock())
    return;

  // LLVMContext &C = M.getContext();
  unsigned int cur_loc = getRandomBasicBlockId();
  ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  IRBuilder<> IRB(&(*IP));

  LoadInst *PrevLoc = IRB.CreateLoad(AngoraPrevLoc);
  setInsNonSan(PrevLoc);

  Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, Int32Ty);
  setValueNonSan(PrevLocCasted);

  // Get Map[idx]
  LoadInst *MapPtr = IRB.CreateLoad(AngoraMapPtr);
  setInsNonSan(MapPtr);

  Value *BrId = IRB.CreateXor(PrevLocCasted, CurLoc);
  setValueNonSan(BrId);
  Value *MapPtrIdx = IRB.CreateGEP(MapPtr, BrId);
  setValueNonSan(MapPtrIdx);

  // Increase 1 : IncRet <- Map[idx] + 1
  LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
  setInsNonSan(Counter);

  // Implementation of saturating counter.
  // Value *CmpOF = IRB.CreateICmpNE(Counter, ConstantInt::get(Int8Ty, -1));
  // setValueNonSan(CmpOF);
  // Value *IncVal = IRB.CreateZExt(CmpOF, Int8Ty);
  // setValueNonSan(IncVal);
  // Value *IncRet = IRB.CreateAdd(Counter, IncVal);
  // setValueNonSan(IncRet);

  // Implementation of Never-zero counter
  // The idea is from Marc and Heiko in AFLPlusPlus
  // Reference: : https://github.com/vanhauser-thc/AFLplusplus/blob/master/llvm_mode/README.neverzero and https://github.com/vanhauser-thc/AFLplusplus/issues/10

  Value *IncRet = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
  setValueNonSan(IncRet);
  Value *IsZero = IRB.CreateICmpEQ(IncRet, ConstantInt::get(Int8Ty, 0));
  setValueNonSan(IsZero);
  Value *IncVal = IRB.CreateZExt(IsZero, Int8Ty);
  setValueNonSan(IncVal);
  IncRet = IRB.CreateAdd(IncRet, IncVal);
  setValueNonSan(IncRet);

  // Store Back Map[idx]
  IRB.CreateStore(IncRet, MapPtrIdx)->setMetadata(NoSanMetaId, NoneMetaNode);

  Value *NewPrevLoc = NULL;
  if (num_fn_ctx != 0) { // Call-based context
    // Load ctx
    LoadInst *CtxVal = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CtxVal);

    Value *CtxValCasted = IRB.CreateZExt(CtxVal, Int32Ty);
    setValueNonSan(CtxValCasted);
    // Udate PrevLoc
    NewPrevLoc =
        IRB.CreateXor(CtxValCasted, ConstantInt::get(Int32Ty, cur_loc >> 1));
  } else { // disable context
    NewPrevLoc = ConstantInt::get(Int32Ty, cur_loc >> 1);
  }
  setValueNonSan(NewPrevLoc);

  StoreInst *Store = IRB.CreateStore(NewPrevLoc, AngoraPrevLoc);
  setInsNonSan(Store);
};

void AngoraLLVMPass::addFnWrap(Function &F) {

  if (num_fn_ctx == 0)
    return;

  // *** Pre Fn ***
  BasicBlock *BB = &F.getEntryBlock();
  Instruction *InsertPoint = &(*(BB->getFirstInsertionPt()));
  IRBuilder<> IRB(InsertPoint);

  Value *CallSite = IRB.CreateLoad(AngoraCallSite);
  setValueNonSan(CallSite);

  Value *OriCtxVal = IRB.CreateLoad(AngoraContext);
  setValueNonSan(OriCtxVal);

  // ***** Add Context *****
  // instrument code before and after each function call to add context
  // We did `xor` simply.
  // This can avoid recursion. The effect of call in recursion will be removed
  // by `xor` with the same value
  // Implementation of function context for AFL by heiko eissfeldt:
  // https://github.com/vanhauser-thc/afl-patches/blob/master/afl-fuzz-context_sensitive.diff
  if (num_fn_ctx > 0) {
    OriCtxVal = IRB.CreateLShr(OriCtxVal, 32 / num_fn_ctx);
    setValueNonSan(OriCtxVal);
  }

  Value *UpdatedCtx = IRB.CreateXor(OriCtxVal, CallSite);
  setValueNonSan(UpdatedCtx);

  StoreInst *SaveCtx = IRB.CreateStore(UpdatedCtx, AngoraContext);
  setInsNonSan(SaveCtx);


  // *** Post Fn ***
  for (auto bb = F.begin(); bb != F.end(); bb++) {
    BasicBlock *BB = &(*bb);
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      // ***** Reload Context *****
      IRBuilder<> Post_IRB(Inst);
      Post_IRB.CreateStore(OriCtxVal, AngoraContext)
          ->setMetadata(NoSanMetaId, NoneMetaNode);
      // ParmeSan: Reset ParmeSanIndCallSite to 0
      resetIndirectCallContext(&Post_IRB);
    }
  }
}

void AngoraLLVMPass::resetIndirectCallContext(IRBuilder<> *IRB) {
  //IRBuilder<> Post_IRB(Inst);
  Constant *NonIndCallSite = ConstantInt::get(Int32Ty, 0);
  StoreInst *SI = IRB->CreateStore(NonIndCallSite, ParmeSanIndCallSite);
  SI->setMetadata(NoSanMetaId, NoneMetaNode);
  setInsNonSan(SI);
}

void AngoraLLVMPass::processCall(Instruction *Inst) {

  CallBase *CI = dyn_cast<CallBase>(Inst);
  Function *fp = CI->getCalledFunction();
  if (fp != NULL) {
    visitCompareFunc(Inst);
    visitExploitation(Inst);
    visitListenCall(Inst);
  }

  //  if (ABIList.isIn(*Callee, "uninstrumented"))
  //  return;
  u32 csid = getRandomContextId();
  Constant *CallSite = ConstantInt::get(Int32Ty, csid);
  IRBuilder<> IRB(Inst);
  if (num_fn_ctx != 0) {
    IRB.CreateStore(CallSite, AngoraCallSite)->setMetadata(NoSanMetaId, NoneMetaNode);
  }

  // Store ParmeSan call site
  if (fp == NULL) {

    IRB.CreateStore(CallSite, ParmeSanIndCallSite)->setMetadata(NoSanMetaId, NoneMetaNode);
  }
}

void AngoraLLVMPass::visitCallInst(Instruction *Inst) {

  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if ((Callee && Callee->isIntrinsic()) || isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  // remove inserted "unfold" functions
  if (Callee && !Callee->getName().compare(StringRef("__unfold_branch_fn"))) {
    if (Caller->use_empty()) {
      Caller->eraseFromParent();
    }
    return;
  }

  processCall(Inst);
};

void AngoraLLVMPass::visitInvokeInst(Instruction *Inst) {

  InvokeInst *Caller = dyn_cast<InvokeInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  processCall(Inst);
}

void AngoraLLVMPass::visitCompareFunc(Instruction *Inst) {
  // configuration file: custom/exploitation_list.txt  fun:xx=cmpfn

  if (!isa<CallBase>(Inst) || !ExploitList.isIn(*Inst, CompareFuncCat)) {
    return;
  }
  ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));

  if (!TrackMode)
    return;

  CallBase *Caller = dyn_cast<CallBase>(Inst);
  Value *OpArg[2];
  OpArg[0] = Caller->getArgOperand(0);
  OpArg[1] = Caller->getArgOperand(1);

  if (!OpArg[0]->getType()->isPointerTy() ||
      !OpArg[1]->getType()->isPointerTy()) {
    return;
  }

  IRBuilder<> IRB(Inst);

  OpArg[0] = IRB.CreatePointerCast(OpArg[0], Int8PtrTy);
  OpArg[1] = IRB.CreatePointerCast(OpArg[1], Int8PtrTy);

  Value *ArgSize = nullptr;
  // If there is a third arguments, it is usually a size argument for compare functions
  if (Caller->getNumArgOperands() > 2) {
    ArgSize = IRB.CreateZExtOrTrunc(Caller->getArgOperand(2),
                                    Int32Ty); // int32ty TODO: in 64bit mode, size_t is 64bit and could be truncated here!!!
  } else {
    ArgSize = ConstantInt::get(Int32Ty, 0);
  }

  LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
  setInsNonSan(CurCtx);

  LoadInst *CallSite = IRB.CreateLoad(ParmeSanIndCallSite);
  setInsNonSan(CallSite);
  CallInst *ProxyCall =
      IRB.CreateCall(TraceFnTT, {Cid, CurCtx, CallSite, ArgSize, OpArg[0], OpArg[1]});
  setInsNonSan(ProxyCall);
  //resetIndirectCallContext(&IRB);
}

Value *AngoraLLVMPass::castArgType(IRBuilder<> &IRB, Value *V) {
  Type *OpType = V->getType();
  Value *NV = V;
  if (OpType->isFloatTy()) {
    NV = IRB.CreateFPToUI(V, Int32Ty);
    setValueNonSan(NV);
    NV = IRB.CreateIntCast(NV, Int64Ty, false);
    setValueNonSan(NV);
  } else if (OpType->isDoubleTy()) {
    NV = IRB.CreateFPToUI(V, Int64Ty);
    setValueNonSan(NV);
  } else if (OpType->isPointerTy()) {
    NV = IRB.CreatePtrToInt(V, Int64Ty);
  } else {
    if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
      NV = IRB.CreateZExt(V, Int64Ty);
    }
  }
  return NV;
}

void AngoraLLVMPass::processCmp(Instruction *Cond, Constant *Cid,
                                Instruction *InsertPoint) {
  CmpInst *Cmp = dyn_cast<CmpInst>(Cond);
  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Type *OpType = OpArg[0]->getType();
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
      OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmp(Cond, Cid, InsertPoint);
    return;
  }
  int num_bytes = OpType->getScalarSizeInBits() / 8;
  if (num_bytes == 0) {
    if (OpType->isPointerTy()) {
      num_bytes = 8;
    } else {
      return;
    }
  }

  IRBuilder<> IRB(InsertPoint);

  if (FastMode) {
    /*
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
    */

    // In FastMode, we only want to check how this one single condition specified in AngoraCondId behaves
    // Therefore, only trigger instrumentation if we are at the currently tracked condition
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNonSan(CmpEq);

    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, InsertPoint, false, ColdCallWeights));
    setInsNonSan(BI);

    IRBuilder<> ThenB(BI);
    OpArg[0] = castArgType(ThenB, OpArg[0]);
    OpArg[1] = castArgType(ThenB, OpArg[1]);
    Value *CondExt = ThenB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    u32 predicate = Cmp->getPredicate();
    if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
      if (CInt->isNegative()) {
        predicate |= COND_SIGN_MASK;
      }
    }
    Value *TypeArg = ConstantInt::get(Int32Ty, predicate);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);

    // TODO: ParmeSan
    LoadInst *CallSite = IRB.CreateLoad(ParmeSanIndCallSite);
    setInsNonSan(CallSite);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, CallSite, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt});
    setInsNonSan(ProxyCall);
    resetIndirectCallContext(&IRB);
  }
}

void AngoraLLVMPass::processBoolCmp(Value *Cond, Constant *Cid,
                                    Instruction *InsertPoint) {
  if (!Cond->getType()->isIntegerTy() ||
      Cond->getType()->getIntegerBitWidth() > 32)
    return;
  Value *OpArg[2];
  OpArg[1] = ConstantInt::get(Int64Ty, 1);
  IRBuilder<> IRB(InsertPoint);
  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNonSan(CmpEq);
    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, InsertPoint, false, ColdCallWeights));
    setInsNonSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = ThenB.CreateZExt(CondExt, Int64Ty);
    setValueNonSan(OpArg[0]);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, 1);
    Value *TypeArg = ConstantInt::get(Int32Ty, COND_EQ_OP | COND_BOOL_MASK);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
    setValueNonSan(OpArg[0]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);

    LoadInst *CallSite = IRB.CreateLoad(ParmeSanIndCallSite);
    setInsNonSan(CallSite);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, CallSite, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt});
    setInsNonSan(ProxyCall);
    resetIndirectCallContext(&IRB);
  }
}

void AngoraLLVMPass::visitCmpInst(Instruction *Inst) {
  Instruction *InsertPoint = Inst->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(Inst))
    return;
  u32 Iid = getInstructionId(Inst);
  CmpMap[Inst] = Iid;
  Constant *Cid = ConstantInt::get(Int32Ty, Iid);
  processCmp(Inst, Cid, InsertPoint);
}

void AngoraLLVMPass::visitBranchInst(Instruction *Inst) {
  BranchInst *Br = dyn_cast<BranchInst>(Inst);
  if (Br->isConditional()) {
    Value *Cond = Br->getCondition();
    if (Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond)) {
      if (!isa<CmpInst>(Cond)) {
        // From  and, or, call, phi ....
        u32 Iid = getInstructionId(Inst);
        CmpMap[Inst] = Iid;
        Constant *Cid = ConstantInt::get(Int32Ty, Iid);
        processBoolCmp(Cond, Cid, Inst);
      }
    }
  }
}

void AngoraLLVMPass::visitSwitchInst(Module &M, Instruction *Inst) {

  SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
  Value *Cond = Sw->getCondition();

  if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
    return;
  }

  int num_bits = Cond->getType()->getScalarSizeInBits();
  int num_bytes = num_bits / 8;
  if (num_bytes == 0 || num_bits % 8 > 0)
    return;

  u32 Iid = getInstructionId(Inst);
  CmpMap[Inst] = Iid;
  Constant *Cid = ConstantInt::get(Int32Ty, Iid);
  IRBuilder<> IRB(Sw);

  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNonSan(CmpEq);
    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, Sw, false, ColdCallWeights));
    setInsNonSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall = ThenB.CreateCall(TraceSw, {Cid, CurCtx, CondExt});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    SmallVector<Constant *, 16> ArgList;
    for (auto It : Sw->cases()) {
      Constant *C = It.getCaseValue();
      if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
        continue;
      ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
    }

    ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
    GlobalVariable *ArgGV = new GlobalVariable(
        M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfInt64Ty, ArgList),
        "__angora_switch_arg_values");
    Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
    Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
    setValueNonSan(ArrPtr);
    Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);

    LoadInst *CallSite = IRB.CreateLoad(ParmeSanIndCallSite);
    setInsNonSan(CallSite);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceSwTT, {Cid, CurCtx, CallSite, SizeArg, CondExt, SwNum, ArrPtr});
    setInsNonSan(ProxyCall);
    resetIndirectCallContext(&IRB);
  }
}

void AngoraLLVMPass::visitExploitation(Instruction *Inst) {
  // For each instruction and called function.
  bool exploit_all = ExploitList.isIn(*Inst, ExploitCategoryAll);
  IRBuilder<> IRB(Inst);
  int numParams = Inst->getNumOperands();
  CallBase *Caller = dyn_cast<CallBase>(Inst);

  if (Caller) {
    numParams = Caller->getNumArgOperands();
  }

  Value *TypeArg =
      ConstantInt::get(Int32Ty, COND_EXPLOIT_MASK | Inst->getOpcode());

  for (int i = 0; i < numParams && i < MAX_EXPLOIT_CATEGORY; i++) {
    if (exploit_all || ExploitList.isIn(*Inst, ExploitCategory[i])) {
      Value *ParamVal = NULL;
      if (Caller) {
        ParamVal = Caller->getArgOperand(i);
      } else {
        ParamVal = Inst->getOperand(i);
      }
      Type *ParamType = ParamVal->getType();
      if (ParamType->isIntegerTy() || ParamType->isPointerTy()) {
        if (!isa<ConstantInt>(ParamVal)) {
          ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
          int size = ParamVal->getType()->getScalarSizeInBits() / 8;
          if (ParamType->isPointerTy()) {
            size = 8;
            ParamVal = IRB.CreatePointerCast(ParamVal, Int64Ty);
          } else if (!ParamType->isIntegerTy(64)) {
            ParamVal = IRB.CreateZExt(ParamVal, Int64Ty);
          }
          Value *SizeArg = ConstantInt::get(Int32Ty, size);

          if (TrackMode) {
            LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
            setInsNonSan(CurCtx);
            LoadInst *CallSite = IRB.CreateLoad(ParmeSanIndCallSite);
            setInsNonSan(CallSite);
            CallInst *ProxyCall = IRB.CreateCall(
                //  Arguments: cmpid: u32, context: u32, last_callsite: u32, size: u32, op: u32, val: u64,
                TraceExploitTT, {Cid, CurCtx, CallSite, SizeArg, TypeArg, ParamVal});
            setInsNonSan(ProxyCall);
            //resetIndirectCallContext(&IRB);
          }
        }
      }
    }
  }
}

bool AngoraLLVMPass::runOnModule(Module &M) {

  SAYF(cCYA "angora-llvm-pass\n");
  if (TrackMode) {
    OKF("Track Mode.");
  } else if (DFSanMode) {
    OKF("DFSan Mode.");
  } else {
    FastMode = true;
    OKF("Fast Mode.");
  }

  initVariables(M);

  if (DFSanMode)
    return true;

  if(!getenv("ANGORA_EARLY_TERMINATION")
     || !strcmp(getenv("ANGORA_EARLY_TERMINATION"),"static")
     || !strcmp(getenv("ANGORA_EARLY_TERMINATION"),"full")) {
    OKF("Adding early termination");
    add_early_termination(M);
  }

  OKF("Hooking dlopen and dlsym (and variants)");
  {
    auto dlopenF = M.getFunction("dlopen");
    if (dlopenF != nullptr) {
      dlopenF->setName("__angora_dlopen");
    }

    auto dlmopenF = M.getFunction("dlmopen");
    if (dlmopenF != nullptr) {
      dlmopenF->setName("__angora_dlmopen");
    }

    auto dlsymF = M.getFunction("dlsym");
    if (dlsymF != nullptr) {
      dlsymF->setName("__angora_dlsym");
    }

    auto dlvsymF = M.getFunction("dlvsym");
    if (dlvsymF != nullptr) {
      dlvsymF->setName("__angora_dlvsym");
    }
  }

  OKF("Iterating over functions");
  for (auto &F : M) {
    if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
      continue;

    llvm::removeUnreachableBlocks(F);

    addFnWrap(F);

    std::vector<BasicBlock *> bb_list;
    for (auto bb = F.begin(); bb != F.end(); bb++)
      bb_list.push_back(&(*bb));

    for (auto bi = bb_list.begin(); bi != bb_list.end(); bi++) {
      BasicBlock *BB = *bi;
      std::vector<Instruction *> inst_list;

      for (auto inst = BB->begin(); inst != BB->end(); inst++) {
        Instruction *Inst = &(*inst);
        inst_list.push_back(Inst);
      }

      for (auto inst = inst_list.begin(); inst != inst_list.end(); inst++) {
        Instruction *Inst = *inst;
        if (Inst->getMetadata(NoSanMetaId))
          continue;
        if (Inst == &(*BB->getFirstInsertionPt())) {
          countEdge(M, *BB);
        }
        if (isa<CallInst>(Inst)) {
          visitCallInst(Inst);
        } else if (isa<InvokeInst>(Inst)) {
          visitInvokeInst(Inst);
        } else if (isa<BranchInst>(Inst)) {
          visitBranchInst(Inst);
        } else if (isa<SwitchInst>(Inst)) {
          visitSwitchInst(M, Inst);
        } else if (isa<CmpInst>(Inst)) {
          visitCmpInst(Inst);
        } else {
          visitExploitation(Inst);
        }
      }
    }
  }

  OKF("Finished instrumentation");

  if (TrackMode) {
    OKF("Exporting CFG");
    export_cfg();
  }

  return true;
}

SinkSourceInfo::SinkSourceInfo(Module &M, const AngoraABIList &ExploitList) : ExploitList(ExploitList) {
  CallGraph CG(M);

  for (scc_iterator<CallGraph *> it = scc_begin(&CG), end = scc_end(&CG); it != end; ++it) {
    this->process_scc(*it);
  }

  for (auto map_entry : this->is_source_map) {
    if (map_entry.second) {
      this->_sources.push_back(map_entry.first);
    }
  }

}

void SinkSourceInfo::process_scc(const std::vector<CallGraphNode *> &cgns) {
  bool scc_header = false;

  // BasicBlocks that should be re-evaluated once the function has been decided
  std::map<Function *, std::set<BasicBlock *>> caller_map;

  // unknown basic blocks
  std::set<BasicBlock *> unknown_bbs;

  // queue of BBs to check next
  std::deque<BasicBlock *> todo;

  //outs() << "PROPAGATING IS_SOURCE INFORMATION\n";

  // first pass over functions
  for (auto &cgn : cgns) {
    //outs() << "=== CGN ===\n";
    Function *func = cgn->getFunction();
    if ((func != nullptr) && (!func->isDeclaration())) {
      //outs() << "\tAdding function " << func->getName() << ":\n";
      for (scc_iterator<Function *> it = scc_begin(func), end = scc_end(func); it != end; ++it) {
        const std::vector<BasicBlock *> &bbs = *it;
        for (auto bb : bbs) {
          auto bb_source_state = this->is_source(bb);
          //outs() << "\t\t" << bb->getParent()->getName() << "[" << bb << "]:  is_source: " << bb_source_state << "\n";
          if (bb_source_state == Unknown) {
            unknown_bbs.insert(bb);
            todo.push_back(bb);
            for (auto &ins : *bb) {
              if (CallBase *cb = dyn_cast<CallBase>(&ins)) {
                auto callee = cb->getCalledFunction();
                caller_map[callee].insert(bb);
              }
            }
          }
        }
      }
    }
  }


  // first check all todo items
  while (!todo.empty()) {
    auto bb = todo.front();
    todo.pop_front();

    // has is been solved in the meantime?
    // if so, just continue with the next one
    if (unknown_bbs.find(bb) == unknown_bbs.end()) {
      continue;
    }

    //outs() << "Checking " << bb->getParent()->getName() << "[" << bb << "], " << todo.size() << " items left...\n";

    auto bb_will_reach_source = this->_lookup(bb, this->will_reach_source_map);
    bool changed = false;

    // check for will_reach_source first, because it can influence can_reach_sink_before_source
    if (bb_will_reach_source == Unknown) {
      bb_will_reach_source = this->_compute_will_reach_source(bb);
      //outs() << "\tchecking for will_reach_source: " << bb_will_reach_source << "\n";
      changed |= bb_will_reach_source != Unknown;
    }

    if (changed) {
      // enqueue unknown predecessors
      for (auto pred: predecessors(bb)) {
        todo.push_back(pred);
      }

      // if this block is entrypoint of a function, also enqueue callers of that function
      auto bb_func = bb->getParent();
      if (&bb_func->getEntryBlock() == bb) {
        for (auto caller : caller_map[bb_func]) {
          todo.push_back(caller);
        }
      }

      // did we solve it?
      // then remove it from the set of unknowns
      if (bb_will_reach_source != Unknown) {
        unknown_bbs.erase(bb);
      }
    }
  }

  // then check remaining unknowns
  // these should all be will_reach_source
  for (auto bb: unknown_bbs) {
    this->will_reach_source_map[bb] = true;
  }

  todo.clear();
  unknown_bbs.clear();

  //outs() << "PROPAGATING IS_SINK_BEFORE_SOURCE INFORMATION\n";
  // second pass over functions
  for (auto &cgn : cgns) {
    //outs() << "=== CGN ===\n";
    Function *func = cgn->getFunction();
    if ((func != nullptr) && (!func->isDeclaration())) {
      //outs() << "\tAdding function " << func->getName() << ":\n";
      for (scc_iterator<Function *> it = scc_begin(func), end = scc_end(func); it != end; ++it) {
        const std::vector<BasicBlock *> &bbs = *it;
        for (auto bb : bbs) {
          auto bb_sink_state = this->is_sink_before_source(bb);
          //outs() << "\t\t" << bb->getParent()->getName() << "[" << bb << "]:  is_sink: "<< bb_sink_state << "\n";
          if (bb_sink_state == Unknown) {
            unknown_bbs.insert(bb);
            todo.push_back(bb);
            for (auto &ins : *bb) {
              if (CallBase *cb = dyn_cast<CallBase>(&ins)) {
                auto callee = cb->getCalledFunction();
                caller_map[callee].insert(bb);
              }
            }
          }
        }
      }
    }
  }


  // first check all todo items
  while (!todo.empty()) {
    auto bb = todo.front();
    todo.pop_front();

    // has is been solved in the meantime?
    // if so, just continue with the next one
    if (unknown_bbs.find(bb) == unknown_bbs.end()) {
      continue;
    }

    //outs() << "Checking " << bb->getParent()->getName() << "[" << bb << "], " << todo.size() << " items left...\n";

    auto bb_can_reach_sink_before_source = this->_lookup(bb, this->can_reach_sink_before_source_map);
    bool changed = false;

    if (bb_can_reach_sink_before_source == Unknown) {
      bb_can_reach_sink_before_source = this->_compute_can_reach_sink_before_source(bb);
      //outs() << "\tchecking for can_reach_sink_before_source: " << bb_can_reach_sink_before_source << "\n";
      changed |= bb_can_reach_sink_before_source != Unknown;
    }

    if (changed) {
      // enqueue unknown predecessors
      for (auto pred: predecessors(bb)) {
        todo.push_back(pred);
      }

      // if this block is entrypoint of a function, also enqueue callers of that function
      auto bb_func = bb->getParent();
      if (&bb_func->getEntryBlock() == bb) {
        for (auto caller : caller_map[bb_func]) {
          todo.push_back(caller);
        }
      }

      // did we solve it?
      // then remove it from the set of unknowns
      if (bb_can_reach_sink_before_source != Unknown) {
        unknown_bbs.erase(bb);
      }
    }
  }

  // then check remaining unknowns
  // these should all be *not* can_reach_sink_before_source
  for (auto bb: unknown_bbs) {
    this->can_reach_sink_before_source_map[bb] = false;
  }
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::is_sink_before_source(Function *F) {
  if (F == nullptr) {
    return Yes; // over-approximate
  }
  //outs() << "Checking is_sink_before_source(" << F->getName()<<"): ";
  if (ExploitList.isIn(*F, SinkCat)) {
    //outs() << "YES (in list)\n";
    return Yes;
  }
  if (F->isDeclaration()) {
    //outs() << "NO (declaration only)\n";
    return No;
  }

  auto res = this->can_reach_sink_before_source(&F->getEntryBlock());
  switch (res) {
  case Yes:
    //outs() << "YES\n";
    break;
  case No:
    //outs() << "NO\n";
    break;
  case Unknown:
    //outs() << "STILL UNKNOWN\n";
    break;
  }
  return res;
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::is_source(Function *F) {
  if (F == nullptr) {
    return No; // under-approximate
  }
  //outs() << "Checking is_source(" << F->getName()<<"): ";
  if (ExploitList.isIn(*F, SourceCat)) {
    //outs() << " YES (in list)\n";
    return Yes;
  }
  if (F->isDeclaration()) {
    //outs() << "NO (declaration only)\n";
    return No;
  }
  auto res = this->will_reach_source(&F->getEntryBlock());
  switch (res) {
  case Yes:
    //outs() << "YES\n";
    break;
  case No:
    //outs() << "NO\n";
    break;
  case Unknown:
    //outs() << "STILL UNKNOWN\n";
    break;
  }
  return res;
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::_compute_is_sink_before_source(BasicBlock *BB) {
  auto sink_state = No;
  for (auto &ins: *BB) {
    if (CallBase *cb = dyn_cast<CallBase>(&ins)) {
      auto callee_is_sink = this->is_sink_before_source(cb->getCalledFunction());
      if (callee_is_sink > sink_state) {
        sink_state = callee_is_sink;
      }
      auto callee_is_source = this->is_source(cb->getCalledFunction());
      if (callee_is_source != No) {
        if (callee_is_source == Unknown) {
          sink_state = Unknown;
        }
        break;
      }
    }
  }
  if (sink_state != Unknown) {
    this->is_sink_before_source_map[BB] = sink_state == Yes;
  }
  return sink_state;
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::_compute_is_source(BasicBlock *BB) {
  auto source_state = SinkSourceInfo::No;
  for (auto &ins: *BB) {
    if (CallBase *cb = dyn_cast<CallBase>(&ins)) {
      auto callee_is_source = this->is_source(cb->getCalledFunction());
      if (callee_is_source > source_state) {
        source_state = callee_is_source;
      }
    }
  }
  if (source_state != Unknown) {
    this->is_source_map[BB] = source_state == Yes;
  }
  return source_state;
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::_lookup(BasicBlock *key, const std::map<BasicBlock *, bool> &map) {
  auto map_entry = map.find(key);
  if (map_entry != map.end()) {
    if (map_entry->second) {
      return Yes;
    } else {
      return No;
    }
  }
  return Unknown;
}
SinkSourceInfo::SinkSourceState SinkSourceInfo::can_reach_sink_before_source(BasicBlock *BB) {
  return this->_lookup(BB, this->can_reach_sink_before_source_map);
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::will_reach_source(BasicBlock *BB) {
  return this->_lookup(BB, this->will_reach_source_map);
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::is_sink_before_source(BasicBlock *BB) {
  return this->_lookup(BB, this->is_sink_before_source_map);
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::is_source(BasicBlock *BB) {
  return this->_lookup(BB, this->is_source_map);
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::_compute_will_reach_source(BasicBlock *BB) {
  auto bb_will_reach_source = this->_compute_is_source(BB);

  if (bb_will_reach_source != Yes) {
    auto all_succs_will_reach_source = Yes;
    bool has_succs = false;

    for (auto succ : successors(BB)) {
      has_succs = true;
      auto succ_will_reach_source = this->will_reach_source(succ);
      if (succ_will_reach_source < all_succs_will_reach_source) {
        all_succs_will_reach_source = succ_will_reach_source;
      }
    }

    if (has_succs && all_succs_will_reach_source > bb_will_reach_source) {
      bb_will_reach_source = all_succs_will_reach_source;
    }

  }

  // definitive result? save it!
  if (bb_will_reach_source != Unknown) {
    this->will_reach_source_map[BB] = bb_will_reach_source == Yes;
  }

  return bb_will_reach_source;
}

SinkSourceInfo::SinkSourceState SinkSourceInfo::_compute_can_reach_sink_before_source(BasicBlock *BB) {
  auto bb_can_reach_sink_before_source = this->_compute_is_sink_before_source(BB);
  auto bb_is_source = this->is_source(BB);

  if (bb_is_source == Unknown && bb_can_reach_sink_before_source != Unknown) {
    errs() << "INCONSISTENCY!!\n";
  }

  if (bb_can_reach_sink_before_source != Yes && bb_is_source == No) {
    auto succs_can_reach_sink_before_source = No;
    bool has_succs = false;

    for (auto succ : successors(BB)) {
      has_succs = true;
      auto succ_can_reach_sink_before_source = this->can_reach_sink_before_source(succ);
      if (succ_can_reach_sink_before_source > succs_can_reach_sink_before_source) {
        succs_can_reach_sink_before_source = succ_can_reach_sink_before_source;
      }
    }

    if (has_succs && succs_can_reach_sink_before_source > bb_can_reach_sink_before_source) {
      bb_can_reach_sink_before_source = succs_can_reach_sink_before_source;
    }

  }

  // definiteve result? save it!
  if (bb_can_reach_sink_before_source != Unknown) {
    this->can_reach_sink_before_source_map[BB] = bb_can_reach_sink_before_source == Yes;
  }

  return bb_can_reach_sink_before_source;
}
const std::vector<BasicBlock *> &SinkSourceInfo::sources() const {
  return this->_sources;
}

void AngoraLLVMPass::add_early_termination(Module &M) {

  std::set<Function *> do_not_modify;

  // A function might return to a block that can then later call another sink.
  // Therefore exclude functions that are called from `can_reach_sink_before_source`-blocks,
  // unless ANGORA_EARLY_AGGRESSIVE is set
  if (!getenv("ANGORA_EARLY_AGGRESSIVE")) {
    for (auto &F : M) {
      for (auto &BB : F) {
        if (SSI->can_reach_sink_before_source(&BB) == SinkSourceInfo::Yes) {
          for (auto &ins : BB) {
            if (CallBase *cb = dyn_cast<CallBase>(&ins)) {
              auto callee = cb->getCalledFunction();
              if (callee) {
                //outs() << callee->getName() << " called from " << F.getName() << ", but BB can reach sink. Marking " << callee->getName() << " as do_not_modify!\n";
              }
              do_not_modify.insert(callee);
            }
          }
        }
      }
    }
  }

  // Now walk from `is_source` blocks and check for edges from `can_reach_sink_before_source` blocks towards blocks that are *not* `can_reach_sink_before_source`
  std::set<BasicBlock *> seen;
  std::deque<BasicBlock *> todo;
  std::set<std::pair<BasicBlock *, BasicBlock *>> edges_to_delete;
  for (auto BB: SSI->sources()) {
    if (do_not_modify.find(BB->getParent()) == do_not_modify.end()) {
      todo.push_back(BB);
    }
  }
  while (!todo.empty()) {
    auto bb = todo.front();
    todo.pop_front();
    if (seen.find(bb) != seen.end()) {
      continue;
    }
    seen.insert(bb);

    for (auto succ: successors(bb)) {
      if (SSI->can_reach_sink_before_source(bb) != SinkSourceInfo::No
          && SSI->can_reach_sink_before_source(succ) == SinkSourceInfo::No) {
        edges_to_delete.emplace(bb, succ);
      } else {
        todo.push_back(succ);
      }
    }
  }

  //outs() << "Found " << edges_to_delete.size() << " edges to be removed\n";

  auto &C = M.getContext();

  std::set<Function *> modified_funcs;

  // Modify successors
  for (auto edge : edges_to_delete) {
    auto from = edge.first;
    auto to = edge.second;
    //outs() << "Removing edge " << from << " -> " << to << "\n";
    auto func = from->getParent();
    assert(func == to->getParent()); // both BBs should be within the same function
    modified_funcs.insert(func);

    // Create check_termination BB
    auto new_check_termination_bb = BasicBlock::Create(C, "terminator", func);
    IRBuilder<> IRB(new_check_termination_bb);
    IRB.CreateCall(CheckTerminate);
    IRB.CreateBr(to);

    // Rewrite the successor
    auto terminator_ins = from->getTerminator();
    terminator_ins->replaceSuccessorWith(to, new_check_termination_bb);
    // Fix PHI-nodes
    to->replacePhiUsesWith(from, new_check_termination_bb);
    // Fix PHI-nodes more (in case we had multiple incoming edges to this block before)
    for (auto &phi : to->phis()) {
      int start_idx = phi.getBasicBlockIndex(new_check_termination_bb);
      for (int i = start_idx + 1; i < phi.getNumIncomingValues();) {
        if (phi.getIncomingBlock(i) == new_check_termination_bb) {
          phi.removeIncomingValue(i);
        } else {
          i++;
        }
      }
    }
  }

  for (auto func : modified_funcs) {
    //func->viewCFG();
  }

  //outs()<< "Done removing edges\n";
}

void AngoraLLVMPass::export_cfg() {

  if (CFGFile.empty()) {
    errs() << "No CFG flename provided!!\n";
    return;
  }

  // build a lightweight cfg over the instrumented comparison instruction
  // = those who occur in CmpMap
  std::set<std::pair<u32, u32>> edges;
  // and keep track of ids that reach a sink
  std::set<u32> targets;

  std::deque<std::pair<u32, const Instruction *>> todo;
  std::set<std::pair<u32, const Instruction *>> seen;

  int from_id = 0;
  const Instruction *ins;
  for (auto kv : CmpMap) {
    ins = kv->first;
    from_id = kv->second;
    todo.push_back(std::make_pair(from_id, ins));
  }

  while (!todo.empty()) {
    from_id = todo.front().first;
    ins = todo.front().second;
    bool done = seen.count(todo.front()) != 0;
    seen.insert(todo.front());
    todo.pop_front();

    // advance until we either find another instrumented instruction
    // or hit the end of the basic block
    while (!(done || ins->isTerminator())) {
      ins = ins->getNextNonDebugInstruction();

      if (const CallBase *CI = dyn_cast<CallBase>(ins)) {
        Function *fp = CI->getCalledFunction();
        if (fp != NULL && (ExploitList.isIn(*fp, SinkCat) || SSI->is_sink_before_source(fp) == SinkSourceInfo::Yes)) {
          targets.insert(from_id);
        }
      }

      if (CmpMap.count(ins) > 0) {
        u32 to_id = CmpMap[ins];
        edges.insert(std::make_pair(from_id, to_id));
        done = true;
      }
    }

    // if we exited the loop because we hit the end of the basicblock,
    // enqueue successing instructions
    if (!done && ins->isTerminator()) {
      for (int i = 0; i < ins->getNumSuccessors(); i++) {
        BasicBlock *next_bb = ins->getSuccessor(i);
        if (!next_bb->empty()) {
          todo.push_back(std::make_pair(from_id, &next_bb->front()));
        }
      }
    }
  }

  std::ofstream outfile(CFGFile);
  writeTargetsJson(outfile, edges, targets);
}

void AngoraLLVMPass::writeTargetsJson(std::basic_ofstream<char> &out,
                                      std::set<std::pair<u32, u32>> &edges,
                                      std::set<u32> &targets) {
  // Print BasicBlock IDs
  out << "{\n" << "\"targets\": [";

  bool first = true;
  for (auto target: targets) {
    if (first) {
      first = false;
    } else {
      out << ", ";
    }
    out << target;
  }
  out << "],\n";
  out << "\"edges\": [";

  first = true;
  for (auto &&e: edges) {
    if (first) {
      first = false;
    } else {
      out << ", ";
    }
    u32 src, dst;
    std::tie(src, dst) = e;
    out << "[" << src << "," << dst << "]";
  }
  out << "],\n";

  // Print Call Site dominators
  out << "\"callsite_dominators\":" << "{";

  /* TODO: Re-add call-site dominators?
   parmesan::IDAssigner::CallSiteDominators CSD = IdAssigner->getCallSiteDominators();
  first = true;
  for (auto const& e: CSD) {
      if (first) {
          first = false;
      } else {
          out << ", ";
      }
      out << "\"" << e.first << "\"" << ": [";
      bool first_inner = true;
      for (auto bb: e.second) {
          if (first_inner)
              first_inner = false;
          else
              out << ", ";
          out << bb;
      }
      out << "]";
  }
   */
  out << "}\n";
  out << "}";
}
void AngoraLLVMPass::visitListenCall(Instruction *Inst) {
  if (!isa<CallBase>(Inst) || !ExploitList.isIn(*Inst, SocketReadyCat)) {
    return;
  }
  OKF("Found a socket instruction \\o/");
  IRBuilder<> IRB(Inst->getNextNode());
  IRB.CreateCall(ListenReady);
}

static void registerAngoraLLVMPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new AngoraLLVMPass());
}

static RegisterPass<AngoraLLVMPass> X("angora_llvm_pass", "Angora LLVM Pass",
                                      false, false);

static RegisterStandardPasses
    RegisterAngoraLLVMPass(PassManagerBuilder::EP_OptimizerLast,
                           registerAngoraLLVMPass);

static RegisterStandardPasses
    RegisterAngoraLLVMPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            registerAngoraLLVMPass);
