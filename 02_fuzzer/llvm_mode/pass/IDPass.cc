#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

static cl::opt<uint64_t> base_id("base_id", cl::desc("base ID (used as xor-mask for branch IDs)"), cl::NotHidden);

namespace {
    class IDLLVMPass : public ModulePass {
    public:
        static char ID;

        IDLLVMPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override;
    };
}

char IDLLVMPass::ID = 0;

bool IDLLVMPass::runOnModule(Module &M) {

    LLVMContext &C = M.getContext();

    unsigned int InsnIdMetaId = C.getMDKindID("instruction_id");

    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

    uint64_t ins_id = 0;
    uint64_t id_mask = base_id.getValue();

    for (Function &F : M) {
        for (BasicBlock &B: F) {
            for (Instruction &I: B) {
                I.setMetadata(InsnIdMetaId,
                              MDNode::get(C, ConstantAsMetadata::get(ConstantInt::get(Int64Ty, id_mask^(ins_id++)))));
            }
        }
    }


    return true;
}

static void registerIDLLVMPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {
    PM.add(new IDLLVMPass());
}

static RegisterPass<IDLLVMPass> X("ID_llvm_pass", "ID LLVM Pass",
                                  false, false);

static RegisterStandardPasses
        RegisterIDLLVMPass(PassManagerBuilder::EP_OptimizerLast,
                           registerIDLLVMPass);

static RegisterStandardPasses
        RegisterIDLLVMPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                            registerIDLLVMPass);