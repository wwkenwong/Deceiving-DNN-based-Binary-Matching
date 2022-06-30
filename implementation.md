# Implementation

Section III-C of the paper has introduced high-level strategies to perturb the control flow structures of an input program. This section further elaborates on the implementation details of each perturbation scheme. Since we implement our approach to directly translating x86 executable, our perturbation passes are particularly implemented for x86 assembly instructions. Nevertheless, it is easy to see that passes adaptive for other languages or architectures (e.g., ARM64) can be easily constructed in the same way.


## Node Rewriting

As discussed in Section III-C, our node rewriting scheme contains two strategies: 
1) Rewriting certain instructions with semantics equivalent instructions, and 
2) Inserting redundant instruction sequences.

### 1. Rewriting certain instructions with semantics equivalent instructions
Regarding the instruction replacement, we leverage three mapping rules to replace certain x86 instructions with their semantics-equivalent instructions. It is worth noting that quite a number of x86 instructions can stealthily change CPU flags. To address this issue, we follow the convention to place a <tt>pushf</tt> instruction right before the replaced instruction to store CPU flags on the stack, and use a <tt>popf</tt> instruction to retrieve the CPU flags from stack right after the replaced instructions.

### 2. Inserting redundant instruction sequences
As for the garbage code insertion, we form a collection of three garbage code sequence candidates which are <tt>nop</tt>, <tt>mov operand, operand</tt>, and <tt>xchg operand, operand</tt>, where each <tt>operand</tt> denotes either a CPU register or a memory address. Each time we will randomly decide to pick <b>N</b> instructions from these collection of meaningless candidates for the insertion. <b>N</b> is empirically decided as 5.

## Subgraph Injection

To insert arbitrary number of new nodes guarded by a so-called opaque predicate, we start by creating a collection of number-theoretic constructions (e.g., <tt>(x*(x-1) \% 2 == 0)</tt>). We note that such number-theoretic constructions will be always evaluated as ```false```. Therefore, it is safe to insert arbitrary number of new nodes on the ```true``` branch without being executed at runtime. Our number-theoretic constructions are first compiled into x86 assembly code routines as the opaque predicate candidates. Our implementation randomly selects one target basic block <b>b</b> from the control flow graph and inserts an opaque predicate ahead of it. We then create a code chunk of <b>N</b> basic blocks (<b>N</b> is 5 in our current implementation) whose contents are randomly created and put this code chunk on the ```true``` branch of the inserted opaque predicate, denoting a garbage subgraph inserted into the original control flow graph.

## Control-Flow Graph Flattening 

The control flow graph flattening scheme transforms an entire function each time; the dispatcher node on top of the flattened control flow graph is implemented as an indirect jump instruction. We hard-code the control destinations of each control transfer into a global buffer. Each time the dispatcher node reads this global buffer and updates the destination of the indirect jump instruction.

## Call Graph Manipulation

For call graph manipulation, we follow conventions in compiler optimization to conduct function inline and extend callsites. In particular, to inline function <b>f</b>, we replace its callsite (i.e., x86 assembly instruction <tt>call</tt>) with all instructions of <b>f</b> except <tt>ret</tt> instructions. We also <tt>push</tt> the address of the instruction next to the callsite at the beginning of <b>f</b> and <tt>pop</tt> it at the end to balance the stack. To create extra callsites, we randomly select certain <tt>jmp</tt> instructions and translate them into a function call instruction toward a ```branch routine```, which redirects the control transfer back to the destinations of the perturbed <tt>jmp</tt> instructions.
