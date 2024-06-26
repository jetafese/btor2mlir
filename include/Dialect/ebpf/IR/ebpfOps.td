//===- ebpfOps.td - ebpf dialect ops -----------*- tablegen -*-===//
//
// This file is licensed under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef EBPF_OPS
#define EBPF_OPS

include "ebpfBase.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "mlir/Interfaces/InferTypeOpInterface.td"
include "mlir/IR/OpAsmInterface.td"
include "mlir/Interfaces/CastInterfaces.td"
include "mlir/Interfaces/VectorInterfaces.td"
include "mlir/IR/BuiltinAttributes.td"

//===----------------------------------------------------------------------===//
// Base ebpf operation definition.
//===----------------------------------------------------------------------===//

class ebpf_Op<string mnemonic, list<Trait> traits = []>
    : Op<ebpf_Dialect, mnemonic, traits>;

def CmpOp : ebpf_Op<"cmp", [
  NoSideEffect, SameTypeOperands,
  TypesMatchWith<"result type has i1 element type and same shape as operands",
                 "lhs", "result", "getI1SameShape($_self)">
] #ElementwiseMappable.traits> {
  // clang-format off
  let summary = "integer comparison operation";
  let description = [{
    The `cmp` operation is a generic comparison for two arguments 
    that need to have their types matching.

    Its first argument is an attribute that defines which type of comparison is
    performed. The following comparisons are supported:

    -   equal (mnemonic: `"eq"`; integer value: `0`)
    -   not equal (mnemonic: `"ne"`; integer value: `1`)
    -   signed less than (mnemonic: `"slt"`; integer value: `2`)
    -   signed less than or equal (mnemonic: `"sle"`; integer value: `3`)
    -   signed greater than (mnemonic: `"sgt"`; integer value: `4`)
    -   signed greater than or equal (mnemonic: `"sge"`; integer value: `5`)
    -   unsigned less than (mnemonic: `"ult"`; integer value: `6`)
    -   unsigned less than or equal (mnemonic: `"ule"`; integer value: `7`)
    -   unsigned greater than (mnemonic: `"ugt"`; integer value: `8`)
    -   unsigned greater than or equal (mnemonic: `"uge"`; integer value: `9`)
    -   equality after bit-wise and (mnemonic: `"set"`; integer value: `10`)

    The result is `1` if the comparison is true and `0` otherwise.

    Example:

    ```mlir
    // Custom form of scalar "signed less than" comparison.
    %x = ebpf.cmp "slt", %lhs, %rhs : !bv<1>
    ```
  }];

  let arguments = (ins ebpfPredicateAttr: $predicate,
                  SignlessIntegerLike: $lhs,
                  SignlessIntegerLike: $rhs);
  
  let results = (outs SignlessIntegerLike : $result);

  let builders = [
    OpBuilder<(ins "ebpfPredicate": $predicate, "Value": $lhs, "Value": $rhs),
      [{
        build($_builder, $_state, ::getI1SameShape(lhs.getType()),
              predicate, lhs, rhs);
      }]>];
  
  let extraClassDeclaration = [{
    static StringRef getPredicateAttrName() { return "predicate"; }
    static ebpfPredicate getPredicateByName(StringRef name);

    ebpfPredicate getPredicate() {
    return (ebpfPredicate)(*this)->getAttrOfType<IntegerAttr>(
            getPredicateAttrName()).getInt();
    }
  }];

  let verifier = [{ return verifyCmpOp(*this); }];
  let assemblyFormat = "$predicate `,` $lhs `,` $rhs attr-dict `:` type($lhs)";
  // clang-format on
}

//===----------------------------------------------------------------------===//
// ebpf binary integer ops definitions
//===----------------------------------------------------------------------===//

// Base class for ebpf arithmetic operations.  Requires operands and
// results to be of the same type, but does not constrain them to specific
// types.
class ebpfArithmeticOp<string mnemonic, list<Trait> traits = []>
    : Op<ebpf_Dialect, mnemonic, traits>;

// This operation takes two operands and returns one result,
// each of these is required to be of the same type.
//  The custom assembly form of the operation is as follows
//
//     <op> %0, %1 : i64
// clang-format off
class ebpfBinaryOp<string mnemonic, list<Trait> traits = []>
  : ebpfArithmeticOp<mnemonic,
                      !listconcat(traits, [SameOperandsAndResultType])>,
    Arguments<(ins SignlessIntegerLike: $lhs, 
                SignlessIntegerLike: $rhs)>,
    Results<(outs SignlessIntegerLike: $result)> {
  let assemblyFormat = "$lhs `,` $rhs attr-dict `:` type($result)";
    // clang-format on
  }

  def AddOp : ebpfBinaryOp<"add", [Commutative]> {
    let summary = "integer addition operation";
    // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.add %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def SubOp : ebpfBinaryOp<"sub"> {
  let summary = "integer subtraction operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.sub %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def MulOp : ebpfBinaryOp<"mul", [Commutative]> {
  let summary = "integer multiplication operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.mul %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def SDivOp : ebpfBinaryOp<"sdiv"> {
  let summary = "integer signed division operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.sdiv %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}


def UDivOp : ebpfBinaryOp<"udiv"> {
  let summary = "integer unsigned division operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.udiv %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def SModOp : ebpfBinaryOp<"smod"> {
  let summary = "integer signed modulus operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.smod %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def UModOp : ebpfBinaryOp<"umod"> {
  let summary = "integer unsigned modulus operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.umod %lhs, %rhs: i64
    ```
  }];
  // clang-format on
}

def OrOp : ebpfBinaryOp<"or", [Commutative]> {
  let summary = "integer binary and operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.or %lhs, %rhs: !bv<32>
    ```
  }];
  // clang-format on
}

def AndOp : ebpfBinaryOp<"and", [Commutative]> {
  let summary = "integer binary and operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.and %lhs, %rhs: !bv<32>
    ```
  }];
  // clang-format on
}

def LSHOp : ebpfBinaryOp<"lsh"> {
  let summary = "integer left logical shift binary operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.lsh %lhs, %rhs: !bv<32>
    ```
  }];
  // clang-format on
}

def RSHOp : ebpfBinaryOp<"rsh"> {
  let summary = "integer right logical shift operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
      ```mlir
      %res = ebpf.rsh %lhs, %rhs: !bv<32>
      ```
  }];
  // clang-format on
}

def ShiftRAOp : ebpfBinaryOp<"arsh"> {
  let summary = "integer right arithmetic shift operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.arsh %lhs, %rhs: !bv<32>
    ```
  }];
  // clang-format on
}

def XOrOp : ebpfBinaryOp<"xor", [Commutative]> {
  let summary = "integer binary xor operation";
  // clang-format off
  let description = [{
    This operation takes two integer arguments and returns an integer.

    Example:
        
    ```mlir
    %res = ebpf.xor %lhs, %rhs: !bv<32>
    ```
  }];
  // clang-format on
}

def MoveOp : ebpfBinaryOp<"move"> {
  let summary = "integer 64bit assignment";
  // clang-format off
  let description = [{
    The `move` operation assigns a 64bit value to another register.
    It takes two operands and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.move %b, %c : i64
    ```
  }];
  // clang-format on
}

def Move32Op : ebpfBinaryOp<"move32"> {
  let summary = "integer 32bit assignment";
  // clang-format off
  let description = [{
    The `move32` operation assigns a 32bit value to another register.
    It takes two operands and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.move32 %b, %c : i64
    ```
  }];
  // clang-format on
}

def Move16Op : ebpfBinaryOp<"move16"> {
  let summary = "integer 16bit assignment";
  // clang-format off
  let description = [{
    The `move32` operation assigns a 16bit value to another register.
    It takes two operands and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.move16 %b, %c : i64
    ```
  }];
  // clang-format on
}

def Move8Op : ebpfBinaryOp<"move8"> {
  let summary = "integer 8bit assignment";
  // clang-format off
  let description = [{
    The `move8` operation assigns a 8bit value to another register.
    It takes two operands and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.move8 %b, %c : i64
    ```
  }];
  // clang-format on
}

def LoadOp : ebpfBinaryOp<"load"> {
  let summary = "memory load operation";
  // clang-format off
  let description = [{
    The `load` operation loads a 64bit value to a register.
    First operand is the base register, second operand is the offset

    Example:

    ```mlir
    %a = ebpf.load %b, %c : i64
    ```
  }];
  // clang-format on
}

def Load32Op : ebpfBinaryOp<"load32"> {
  let summary = "memory load32 operation";
  // clang-format off
  let description = [{
    The `load32` operation loads a 32bit value to a register.
    First operand is the base register, second operand is the offset

    Example:

    ```mlir
    %a = ebpf.load32 %b, %c : i64
    ```
  }];
  // clang-format on
}

def Load16Op : ebpfBinaryOp<"load16"> {
  let summary = "memory load16 operation";
  // clang-format off
  let description = [{
    The `load16` operation loads a 16bit value to a register.
    First operand is the base register, second operand is the offset

    Example:

    ```mlir
    %a = ebpf.load16 %b, %c : i64
    ```
  }];
  // clang-format on
}

def Load8Op : ebpfBinaryOp<"load8"> {
  let summary = "memory load8 operation";
  // clang-format off
  let description = [{
    The `load8` operation loads a 8bit value to a register.
    First operand is the base register, second operand is the offset

    Example:

    ```mlir
    %a = ebpf.load8 %b, %c : i64
    ```
  }];
  // clang-format on
}

def LoadMapOp : ebpfBinaryOp<"loadMap"> {
  let summary = "load map operation";
  // clang-format off
  let description = [{
    The `loadMap` operation loads a value to a register.
    First operand is the target register, second operand is the map

    Example:

    ```mlir
    %a = ebpf.loadMap %b, %c : i64
    ```
  }];
  // clang-format on
}

//===----------------------------------------------------------------------===//
// ebpf unary integer ops definitions
//===----------------------------------------------------------------------===//

// Base class for unary ops. Requires single operand and result. Individual
// classes will have `operand` accessor.
// clang-format off
class ebpfUnaryOp<string mnemonic, list<Trait> traits = []>
    : Op<ebpf_Dialect, mnemonic,
         !listconcat(traits, [NoSideEffect, SameOperandsAndResultType])>,
      Arguments<(ins SignlessIntegerLike: $operand)>,
      Results<(outs SignlessIntegerLike: $result)> {

  let assemblyFormat = "$operand attr-dict `:` type($result)";
  // clang-format on
}

def NegOp : ebpfUnaryOp<"neg"> {
  let summary = "integer negation";
  // clang-format off
  let description = [{
    The `neg` operation computes the negation of a given value.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    // Scalar negation value.
    %a = ebpf.neg %b: i64
    ```
  }];
  // clang-format on
}

def BE16 : ebpfUnaryOp<"be16"> {
  let summary = "integer big endian byte order";
  // clang-format off
  let description = [{
    The `htobe16` operation assigns host bits to big endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.be16 %b: i64
    ```
  }];
  // clang-format on
}

def BE32 : ebpfUnaryOp<"be32"> {
  let summary = "integer big endian byte order";
  // clang-format off
  let description = [{
    The `htobe32` operation assigns host bits to big endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.be32 %b: i64
    ```
  }];
  // clang-format on
}

def BE64 : ebpfUnaryOp<"be64"> {
  let summary = "integer big endian byte order";
  // clang-format off
  let description = [{
    The `htobe64` operation assigns host bits to big endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.be64 %b: i64
    ```
  }];
  // clang-format on
}

def LE16 : ebpfUnaryOp<"le16"> {
  let summary = "integer little endian byte order";
  // clang-format off
  let description = [{
    The `htobe16` operation assigns host bits to little endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.le16 %b: i16
    ```
  }];
  // clang-format on
}

def LE32 : ebpfUnaryOp<"le32"> {
  let summary = "integer little endian byte order";
  // clang-format off
  let description = [{
    The `htobe32` operation assigns host bits to little endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.le32 %b: i32
    ```
  }];
  // clang-format on
}

def LE64 : ebpfUnaryOp<"le64"> {
  let summary = "integer little endian byte order";
  // clang-format off
  let description = [{
    The `htobe64` operation assigns host bits to little endian.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.le64 %b: i64
    ```
  }];
  // clang-format on
}

def SWAP16 : ebpfUnaryOp<"swap16"> {
  let summary = "integer swap operation";
  // clang-format off
  let description = [{
    The `bwsap16` operation unconditionally reverses the 
    order of bytes.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.bswap16 %b: i64
    ```
  }];
  // clang-format on
}

def SWAP32 : ebpfUnaryOp<"swap32"> {
  let summary = "integer swap operation";
  // clang-format off
  let description = [{
    The `bwsap32` operation unconditionally reverses the 
    order of bytes.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.bswap32 %b: i64
    ```
  }];
  // clang-format on
}

def SWAP64 : ebpfUnaryOp<"swap64"> {
  let summary = "integer swap operation";
  // clang-format off
  let description = [{
    The `bwsap64` operation unconditionally reverses the 
    order of bytes.
    It takes one operand and returns one result of the same type.

    Example:

    ```mlir
    %a = ebpf.bswap64 %b: i64
    ```
  }];
  // clang-format on
}

def AllocaOp : ebpf_Op<"alloca"> {
  let summary = "alloca op";
  // clang-format off
  let description = [{
    The `alloca` operation takes nothing returns a 64bit 
    int to use as a pointer.

    Example:

    ```mlir
    %a = ebpf.alloca %s : i64
    ```
  }];
  let results = (outs SignlessIntegerLike : $result);
  let assemblyFormat = " attr-dict `:` type($result)";
  // clang-format on
}

def NDOp : ebpf_Op<"nd"> {
  let summary = "integer non-deterministic value";
  // clang-format off
  let description = [{
    The `nd` operation takes no operands and returns a 64bit 
    non-deterministic integer.

    Example:

    ```mlir
    %a = ebpf.nd : i64
    ```
  }];
  let results = (outs SignlessIntegerLike : $result);
  let assemblyFormat = " attr-dict `:` type($result)";
  // clang-format on
}


def ConstantOp : ebpf_Op<"constant", [ConstantLike, NoSideEffect]> {
  let summary = "integer constant";
  // clang-format off
  let description = [{
    The `constant` operation produces an SSA value equal to some constant
        specified by an attribute.

    Example:

    ```mlir
    // Integer constant
    %1 = ebpf.constant 42: i64
    ```
  }];
  let arguments = (ins Builtin_IntegerAttr : $value);
  let results = (outs SignlessIntegerLike : $result);
  let assemblyFormat = "attr-dict $value type($result)";
  let verifier = [{ return verifyConstantOp(*this); }];
  // clang-format on
}

def AssertOp : ebpf_Op<"assertt"> {
  let summary = "ebpf assertion";
  // clang-format off
  let description = [{
    This operation takes one boolean argument and terminates
    the program if the condition does not hold.

    Example :
    
    ```mlir
    // Apply the assert operation to %0
    ebpf.assert(%0)
    ```
  }];
  let arguments = (ins I1 : $arg);
  let assemblyFormat = "`(` $arg `)` attr-dict `,` type($arg)";
  // clang-format on
}

// This operation takes three operands and returns no result,
// each operand is required to be of the same type.
//  The custom assembly form of the operation is as follows
//
//     <op> %0, %1, %2: i64
// clang-format off
class ebpfTernaryOp<string mnemonic, list<Trait> traits = []>
  : ebpfArithmeticOp<mnemonic,
                      !listconcat(traits, [SameTypeOperands])>,
    Arguments<(ins SignlessIntegerLike: $lhs, 
                SignlessIntegerLike: $offset,
                SignlessIntegerLike: $rhs)>
{
  let assemblyFormat = "$lhs `,` $offset `,` $rhs attr-dict `:` type($lhs)";
// clang-format on
}

def StoreOp : ebpfTernaryOp<"store"> {
  let summary = "memory store operation";
  // clang-format off
  let description = [{
    The `store` operation stores a 64bit value to a register.
    First operand is the base register, second operand is the offset.
    Third operand is the value/register to be written.

    Example:

    ```mlir
    ebpf.store %a, %b, %c : i64
    ```
  }];
  // clang-format on
}

def Store32Op : ebpfTernaryOp<"store32"> {
  let summary = "memory store32 operation";
  // clang-format off
  let description = [{
    The `store32` operation stores a 32bit value to a register.
    First operand is the base register, second operand is the offset.
    Third operand is the value/register to be written.

    Example:

    ```mlir
    ebpf.store32 %a, %b, %c : i64
    ```
  }];
  // clang-format on
}

def Store16Op : ebpfTernaryOp<"store16"> {
  let summary = "memory store16 operation";
  // clang-format off
  let description = [{
    The `store16` operation stores a 16bit value to a register.
    First operand is the base register, second operand is the offset.
    Third operand is the value/register to be written.

    Example:

    ```mlir
    ebpf.store16 %a, %b, %c : i64
    ```
  }];
  // clang-format on
}

def Store8Op : ebpfTernaryOp<"store8"> {
  let summary = "memory store8 operation";
  // clang-format off
  let description = [{
    The `store8` operation stores a 8bit value to a register.
    First operand is the base register, second operand is the offset.
    Third operand is the value/register to be written.

    Example:

    ```mlir
    ebpf.store8 %a, %b, %c : i64
    ```
  }];
  // clang-format on
}

#endif // EBPF_OPS
