#include "Conversion/ebpfToLLVM/ConvertebpfToLLVMPass.h"
#include "Dialect/ebpf/IR/ebpf.h"

#include "../PassDetail.h"
#include "mlir/Conversion/LLVMCommon/ConversionTarget.h"
#include "mlir/Conversion/LLVMCommon/VectorPattern.h"
#include "mlir/Conversion/StandardToLLVM/ConvertStandardToLLVM.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/Dialect/MemRef/IR/MemRef.h"
#include "mlir/IR/TypeRange.h"
#include "mlir/IR/TypeUtilities.h"

#include <string>

using namespace mlir;

#define PASS_NAME "convert-ebpf-to-llvm"
#define MINUS1_32 4294967295
#define MINUS1_16 65535
#define MINUS1_8 255

namespace {

//===----------------------------------------------------------------------===//
// Straightforward Op Lowerings
//===----------------------------------------------------------------------===//
#define CONVERT_OP(EBPF, LLVM) mlir::VectorConvertToLLVMPattern<EBPF, LLVM>

/** division operations will need to abort when dividing by zero **/
using SDivOpLowering = CONVERT_OP(ebpf::SDivOp, LLVM::SDivOp);
using UDivOpLowering = CONVERT_OP(ebpf::UDivOp, LLVM::UDivOp);
using SModOpLowering = CONVERT_OP(ebpf::SModOp, LLVM::SRemOp);
using UModOpLowering = CONVERT_OP(ebpf::UModOp, LLVM::URemOp);

using AddOpLowering = CONVERT_OP(ebpf::AddOp, LLVM::AddOp);
using SubOpLowering = CONVERT_OP(ebpf::SubOp, LLVM::SubOp);
using MulOpLowering = CONVERT_OP(ebpf::MulOp, LLVM::MulOp);
using OrOpLowering = CONVERT_OP(ebpf::OrOp, LLVM::OrOp);
using XOrOpLowering = CONVERT_OP(ebpf::XOrOp, LLVM::XOrOp);
using ShiftLLOpLowering = CONVERT_OP(ebpf::LSHOp, LLVM::ShlOp);
using ShiftRLOpLowering = CONVERT_OP(ebpf::RSHOp, LLVM::LShrOp);
using ShiftRAOpLowering = CONVERT_OP(ebpf::ShiftRAOp, LLVM::AShrOp);
using AndOpLowering = CONVERT_OP(ebpf::AndOp, LLVM::AndOp);

//===----------------------------------------------------------------------===//
// Op Lowerings
//===----------------------------------------------------------------------===//

// Convert ebpf.cmp predicate into the LLVM dialect CmpPredicate.
// template <typename LLVMPredType>
static LLVM::ICmpPredicate convertCmpPredicate(ebpf::ebpfPredicate pred) {
  assert(pred != ebpf::ebpfPredicate::set && "set not implemented");
  return static_cast<LLVM::ICmpPredicate>(pred);
}

struct CmpOpLowering : public ConvertOpToLLVMPattern<ebpf::CmpOp> {
  using ConvertOpToLLVMPattern<ebpf::CmpOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::CmpOp op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto resultType = op.getResult().getType();

    rewriter.replaceOpWithNewOp<LLVM::ICmpOp>(
        op, typeConverter->convertType(resultType),
        convertCmpPredicate(op.getPredicate()), adaptor.lhs(), adaptor.rhs());

    return success();
  }
};

struct ConstantOpLowering : public ConvertOpToLLVMPattern<ebpf::ConstantOp> {
  using ConvertOpToLLVMPattern<ebpf::ConstantOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::ConstantOp op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    return LLVM::detail::oneToOneRewrite(
        op, LLVM::ConstantOp::getOperationName(), adaptor.getOperands(),
        *getTypeConverter(), rewriter);
  }
};

struct NegOpLowering : public ConvertOpToLLVMPattern<ebpf::NegOp> {
  using ConvertOpToLLVMPattern<ebpf::NegOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::NegOp negOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    Value operand = adaptor.operand();
    Type opType = operand.getType();

    Value zeroConst = rewriter.create<LLVM::ConstantOp>(
        negOp.getLoc(), opType, rewriter.getIntegerAttr(opType, 0));
    rewriter.replaceOpWithNewOp<LLVM::SubOp>(negOp, zeroConst, operand);
    return success();
  }
};

struct StoreOpLowering : public ConvertOpToLLVMPattern<ebpf::StoreOp> {
  using ConvertOpToLLVMPattern<ebpf::StoreOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::StoreOp storeOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = storeOp.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.offset();
    auto val = adaptor.rhs();

    Value addr = rewriter.create<LLVM::AddOp>(loc, base, offset);
    auto reg = rewriter.create<LLVM::IntToPtrOp>(
        loc, LLVM::LLVMPointerType::get(rewriter.getI64Type()), addr);
    rewriter.replaceOpWithNewOp<LLVM::StoreOp>(storeOp, val, reg);
    return success();
  }
};

struct Store8OpLowering : public ConvertOpToLLVMPattern<ebpf::Store8Op> {
  using ConvertOpToLLVMPattern<ebpf::Store8Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Store8Op store8Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = store8Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.offset();
    auto val = adaptor.rhs();
    /* mask to isolate the 8bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_8));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::StoreOp>(store8Op, base, offset, newVal);
    return success();
  }
};

struct Store16OpLowering : public ConvertOpToLLVMPattern<ebpf::Store16Op> {
  using ConvertOpToLLVMPattern<ebpf::Store16Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Store16Op store16Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = store16Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.offset();
    auto val = adaptor.rhs();
    /* mask to isolate the 16bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_16));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::StoreOp>(store16Op, base, offset, newVal);
    return success();
  }
};

struct Store32OpLowering : public ConvertOpToLLVMPattern<ebpf::Store32Op> {
  using ConvertOpToLLVMPattern<ebpf::Store32Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Store32Op store32Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = store32Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.offset();
    auto val = adaptor.rhs();
    /* mask to isolate the 32bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_32));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::StoreOp>(store32Op, base, offset, newVal);
    return success();
  }
};

struct LoadOpLowering : public ConvertOpToLLVMPattern<ebpf::LoadOp> {
  using ConvertOpToLLVMPattern<ebpf::LoadOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::LoadOp loadOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = loadOp.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.rhs();

    Value addr = rewriter.create<LLVM::AddOp>(loc, base, offset);
    auto reg = rewriter.create<LLVM::IntToPtrOp>(
        loc, LLVM::LLVMPointerType::get(rewriter.getI64Type()), addr);
    rewriter.replaceOpWithNewOp<LLVM::LoadOp>(loadOp, reg);
    return success();
  }
};

struct Load8OpLowering : public ConvertOpToLLVMPattern<ebpf::Load8Op> {
  using ConvertOpToLLVMPattern<ebpf::Load8Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Load8Op load8Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = load8Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.rhs();
    auto val = rewriter.create<ebpf::LoadOp>(loc, base, offset);
    /* mask to isolate the 8bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_8));
    rewriter.replaceOpWithNewOp<LLVM::AndOp>(load8Op, val, mask);
    return success();
  }
};

struct Load16OpLowering : public ConvertOpToLLVMPattern<ebpf::Load16Op> {
  using ConvertOpToLLVMPattern<ebpf::Load16Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Load16Op load16Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = load16Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.rhs();
    auto val = rewriter.create<ebpf::LoadOp>(loc, base, offset);
    /* mask to isolate the 16bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_16));
    rewriter.replaceOpWithNewOp<LLVM::AndOp>(load16Op, val, mask);
    return success();
  }
};

struct Load32OpLowering : public ConvertOpToLLVMPattern<ebpf::Load32Op> {
  using ConvertOpToLLVMPattern<ebpf::Load32Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Load32Op load32Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = load32Op.getLoc();
    auto base = adaptor.lhs(), offset = adaptor.rhs();
    auto val = rewriter.create<ebpf::LoadOp>(loc, base, offset);
    /* mask to isolate the 32bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_32));
    rewriter.replaceOpWithNewOp<LLVM::AndOp>(load32Op, val, mask);
    return success();
  }
};

struct MoveOpLowering : public ConvertOpToLLVMPattern<ebpf::MoveOp> {
  using ConvertOpToLLVMPattern<ebpf::MoveOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::MoveOp moveOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = moveOp.getLoc();
    auto dst = adaptor.lhs(), val = adaptor.rhs();
    auto zero = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(0));
    rewriter.replaceOpWithNewOp<ebpf::StoreOp>(moveOp, dst, zero, val);
    return success();
  }
};

struct Move8OpLowering : public ConvertOpToLLVMPattern<ebpf::Move8Op> {
  using ConvertOpToLLVMPattern<ebpf::Move8Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Move8Op move8Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = move8Op.getLoc();
    auto val = adaptor.rhs();
    /* mask to isolate the 8bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_8));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::MoveOp>(move8Op, adaptor.lhs(), newVal);
    return success();
  }
};

struct Move16OpLowering : public ConvertOpToLLVMPattern<ebpf::Move16Op> {
  using ConvertOpToLLVMPattern<ebpf::Move16Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Move16Op move16Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = move16Op.getLoc();
    auto val = adaptor.rhs();
    /* mask to isolate the 16bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_16));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::MoveOp>(move16Op, adaptor.lhs(), newVal);
    return success();
  }
};

struct Move32OpLowering : public ConvertOpToLLVMPattern<ebpf::Move32Op> {
  using ConvertOpToLLVMPattern<ebpf::Move32Op>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::Move32Op move32Op, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = move32Op.getLoc();
    auto val = adaptor.rhs();
    /* mask to isolate the 32bits*/
    auto mask = rewriter.create<LLVM::ConstantOp>(
        loc, rewriter.getI64Type(), rewriter.getI64IntegerAttr(MINUS1_32));
    auto newVal = rewriter.create<LLVM::AndOp>(loc, val, mask);
    rewriter.replaceOpWithNewOp<ebpf::MoveOp>(move32Op, adaptor.lhs(), newVal);
    return success();
  }
};

struct LoadMapOpLowering : public ConvertOpToLLVMPattern<ebpf::LoadMapOp> {
  using ConvertOpToLLVMPattern<ebpf::LoadMapOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::LoadMapOp loadMapOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    const std::string map = "BPF_LD_MAP_FD";
    auto mapDescriptor = adaptor.rhs();
    auto module = loadMapOp->getParentOfType<ModuleOp>();
    auto mapFunc = module.lookupSymbol<LLVM::LLVMFuncOp>(map);
    if (!mapFunc) {
      OpBuilder::InsertionGuard guard(rewriter);
      rewriter.setInsertionPointToStart(module.getBody());
      auto mapFuncTy = LLVM::LLVMFunctionType::get(rewriter.getI64Type(),
                                                   {rewriter.getI64Type()});
      mapFunc = rewriter.create<LLVM::LLVMFuncOp>(rewriter.getUnknownLoc(), map,
                                                  mapFuncTy);
    }
    rewriter.replaceOpWithNewOp<LLVM::CallOp>(loadMapOp, mapFunc,
                                              mapDescriptor);
    return success();
  }
};

struct NDOpLowering : public ConvertOpToLLVMPattern<ebpf::NDOp> {
  using ConvertOpToLLVMPattern<ebpf::NDOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::NDOp ndOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    /* we resolve with an nd call for now*/
    const std::string havoc = "nd_64";
    auto module = ndOp->getParentOfType<ModuleOp>();
    auto havocFunc = module.lookupSymbol<LLVM::LLVMFuncOp>(havoc);
    if (!havocFunc) {
      OpBuilder::InsertionGuard guard(rewriter);
      rewriter.setInsertionPointToStart(module.getBody());
      auto havocFuncTy = LLVM::LLVMFunctionType::get(rewriter.getI64Type(), {});
      havocFunc = rewriter.create<LLVM::LLVMFuncOp>(rewriter.getUnknownLoc(),
                                                    havoc, havocFuncTy);
    }
    rewriter.replaceOpWithNewOp<LLVM::CallOp>(ndOp, havocFunc, llvm::None);
    return success();
  }
};

struct AllocaOpLowering : public ConvertOpToLLVMPattern<ebpf::AllocaOp> {
  using ConvertOpToLLVMPattern<ebpf::AllocaOp>::ConvertOpToLLVMPattern;
  LogicalResult
  matchAndRewrite(ebpf::AllocaOp allocaOp, OpAdaptor adaptor,
                  ConversionPatternRewriter &rewriter) const override {
    auto loc = allocaOp.getLoc();
    auto i64Type = rewriter.getI64Type();
    auto size = rewriter.create<LLVM::ConstantOp>(
        loc, i64Type, rewriter.getI64IntegerAttr(1));
    auto llvmAlloca = rewriter.create<LLVM::AllocaOp>(
        loc, LLVM::LLVMPointerType::get(i64Type), size, 8);
    rewriter.replaceOpWithNewOp<LLVM::PtrToIntOp>(allocaOp, i64Type,
                                                  llvmAlloca);
    return success();
  }
};
} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Pass Definition
//===----------------------------------------------------------------------===//

namespace {

struct ebpfToLLVMLoweringPass
    : public ConvertebpfToLLVMBase<ebpfToLLVMLoweringPass> {

  ebpfToLLVMLoweringPass() = default;

  void getDependentDialects(DialectRegistry &registry) const override {
    registry.insert<LLVM::LLVMDialect>();
  }
  StringRef getArgument() const final { return PASS_NAME; }
  void runOnOperation() override;
};
} // end anonymous namespace

void ebpfToLLVMLoweringPass::runOnOperation() {
  LLVMConversionTarget target(getContext());
  RewritePatternSet patterns(&getContext());
  ebpfToLLVMTypeConverter converter(&getContext(), true);

  mlir::ebpf::populateebpfToLLVMConversionPatterns(converter, patterns);
  mlir::populateStdToLLVMConversionPatterns(converter, patterns);

  /// Configure conversion to lift ebpf; Anything else is fine.
  /// unary operators
  target.addIllegalOp<ebpf::NegOp, ebpf::BE16, ebpf::BE32, ebpf::BE64,
                      ebpf::LE16, ebpf::LE32, ebpf::LE64, ebpf::SWAP16,
                      ebpf::SWAP32, ebpf::SWAP64>();

  /// misc operators
  target.addIllegalOp<ebpf::ConstantOp, ebpf::NDOp, ebpf::AllocaOp>();

  /// binary operators
  // logical
  target.addIllegalOp<ebpf::CmpOp, ebpf::LSHOp, ebpf::RSHOp, ebpf::ShiftRAOp,
                      ebpf::XOrOp, ebpf::OrOp, ebpf::AndOp>();

  // arithmetic
  target.addIllegalOp<ebpf::AddOp, ebpf::SubOp, ebpf::MulOp, ebpf::SDivOp,
                      ebpf::UDivOp, ebpf::SModOp, ebpf::UModOp, ebpf::MoveOp,
                      ebpf::Move32Op, ebpf::Move16Op, ebpf::Move8Op,
                      ebpf::LoadMapOp>();

  /// ternary operators
  target.addIllegalOp<ebpf::StoreOp, ebpf::Store32Op, ebpf::Store16Op,
                      ebpf::Store8Op, ebpf::LoadOp, ebpf::Load32Op,
                      ebpf::Load16Op, ebpf::Load8Op>();

  if (failed(applyPartialConversion(getOperation(), target,
                                    std::move(patterns)))) {
    signalPassFailure();
  }
}

//===----------------------------------------------------------------------===//
// Populate Lowering Patterns
//===----------------------------------------------------------------------===//

void mlir::ebpf::populateebpfToLLVMConversionPatterns(
    ebpfToLLVMTypeConverter &converter, RewritePatternSet &patterns) {
  patterns.add<
      AddOpLowering, SubOpLowering, MulOpLowering, SModOpLowering,
      UModOpLowering, AndOpLowering, SDivOpLowering, UDivOpLowering,
      NegOpLowering, OrOpLowering, XOrOpLowering, ShiftLLOpLowering,
      ShiftRLOpLowering, ShiftRAOpLowering, CmpOpLowering, ConstantOpLowering,
      StoreOpLowering, Store8OpLowering, Store16OpLowering, Store32OpLowering,
      LoadOpLowering, Load8OpLowering, Load16OpLowering, Load32OpLowering,
      MoveOpLowering, Move8OpLowering, Move16OpLowering, Move32OpLowering,
      LoadMapOpLowering, NDOpLowering, AllocaOpLowering>(converter);
}

/// Create a pass for lowering operations the remaining `ebpf` operations
// to the LLVM dialect for codegen.
std::unique_ptr<mlir::Pass> mlir::ebpf::createLowerToLLVMPass() {
  return std::make_unique<ebpfToLLVMLoweringPass>();
}
