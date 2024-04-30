# cr3CTF 2024
## RE: warmup
This challenge is a simple flag checker program which takes in our input and returns whether the flag is correct. When we first load the binary into IDA, it the decompilation fails because of the instructions 
```
.text:000000000000185F 058 enter   0FFFFFFFFFFFFFFFFh, 0FFh
```
which the decompiler fails to analyse. We can patch these instructions out with `nop`s, since it does not affect the functionality of the program, and the decompiler will work again. 

Out of curiosity, I wanted to check if angr was able to lift and symbolically execute these instructions. It turns out it was able to lift and infer that these instructions do not have any side effect to the program's state.
```
In [11]: p.factory.block(0x40185f).vex.pp()
IRSB {


   NEXT: PUT(rip) = 0x000000000040185f; Ijk_NoDecode
}
```
Looking at the last block in the `main` function, we see that in order for this program to return that our input is true, we need to let `rax` to be equal to `rcx` at `0x402963`.
```
.text:000000000000295F 2558 adc     edx, ecx
.text:0000000000002961 2558 mov     ecx, edx
.text:0000000000002963 2558 cmp     rax, rcx
.text:0000000000002966 2558 lea     rax, aThatSRight ; "that's right!\n"
.text:000000000000296D 2558 lea     rdi, aNope     ; "nope\n"
.text:0000000000002974 2558 cmovz   rdi, rax       ; format
.text:0000000000002978 2558 xor     eax, eax
.text:000000000000297A 2558 call    _printf
```
Hence, we let angr symbolically execute the program up till the address `0x402963`, set an additional constraint of `rax == rcx`. Lastly, we ask angr to solve for all the constraints imposed on `stdin` and dump it out to us.

```python
import angr, monkeyhex

p = angr.Project('chall', load_options={'auto_load_libs': False})
state = p.factory.entry_state()
simgr = p.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.Veritesting())
simgr.explore(find=0x402963)
if simgr.found:
    for solution_state in simgr.found:
        solution_state.solver.add(solution_state.regs.rax == solution_state.regs.rcx)
        try:
            print(f"found: {solution_state.posix.dumps(0).decode()}")
        except Exception as e:
            print(f"{e}: skip solution")
else:
    raise Exception('no solution')
```

Flag: `cr3{d0nt_trU5t_D3c0mp1L3rs_t0o_muCh}`