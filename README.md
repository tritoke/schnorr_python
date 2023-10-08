# schnorr_python
A toy implementation of the Schnorr Signature Scheme and ID protocol in Python.

## Example Output

```py
Schnorr interactive ID protocol:
50720782574909136199281371936859173723502013811045152240636260116882190273270
public: pk=1041850277563560424518990965567459599555199991524148435030406317200207641392461405313144065017119255566076380150291103377681744621923285941777603368823625

╲‾ ‾ ‾ commit=3589282322478799979615960686271655640700866050358407158334519039242167863851922201944394626714425392641906404856208858602290075276504803554304267729108803
 ╲
 🮥     chall=42167132120971331634369376156663100513263987976552921685374961035908958454357
 ╱
╱_ _ _ resp=50720782574909136199281371936859173723502013811045152240636260116882190273270

victor trusts peggy ✨

Schnorr signatures from the fiat-shamir heuristic:
Peggy's signature for the message "bears ❤  twinks": (2548361619366491401394359350638284527161037026397935057347950481852333486884905913403519154139404929031031489790422056641037121538962068337309468801195294, 54324459466469923352187862827100734686662756015441290527874935885843308490314)
54324459466469923352187862827100734686662756015441290527874935885843308490314
Victor trusts Peggy's signature 🥲
```
