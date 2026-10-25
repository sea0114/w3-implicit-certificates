"""Evaluate existing T4 P9/P12 and T5 W12-10/14/15, not attack estimates."""
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path
import json
import csv

QORDER=52435875175126190479447740508185965837690552500527637822603658699938581184513


def evaluate(kind, lam=128, h=2**32, issuance=2**20, exposure=2**20,
             L=1, k=128, outer=144, n=8, eps=Fraction(1,2**32), gamma=Fraction(1,2**128)):
    if kind not in ('PS','Waters') or not 1 < 2**lam < QORDER:
        raise ValueError('parameter domain')
    if min(h,issuance,exposure,n)<0 or min(L,k,outer)<1:
        raise ValueError('budget')
    M=QORDER**(2 if kind=='PS' else 1)
    queries=h+1
    d=2**lam
    loss=min(Fraction(1),Fraction(issuance*h+issuance*(issuance-1)//2,M))
    sampler=Fraction(issuance,2**k)
    tau=Fraction(1 if kind=='PS' else n+1,2**outer)
    e0=max(Fraction(0),eps-loss-sampler)
    lower=max(Fraction(0),e0*max(Fraction(0),e0/queries-Fraction(1,d))-tau)
    ne=min(Fraction(1),Fraction(exposure,M**L)) + Fraction(2+2*exposure*L,2**k)+tau
    sh=Fraction(2,2**k)+tau
    with localcontext() as ctx:
        ctx.prec=100
        dec=lambda x: Decimal(x.numerator)/Decimal(x.denominator)
        # Use the published looser comparison, without presenting algebraic
        # sharpening as a new result. gamma is an assumed solver advantage cap.
        upper=dec(loss+sampler+Fraction(queries,d))+(Decimal(queries)*dec(gamma+tau)).sqrt()
        def fmt(x): return f'{dec(x):.12E}'
        return {'kind':kind,'lambda':lam,'qH':h,'qI':issuance,'qX':exposure,'L':L,
                'k_inner':k,'k_outer':outer,'n':n,'epsilon_scenario':fmt(eps),
                'gamma_assumed':fmt(gamma),'issuance_loss':fmt(loss),'inner_tail':fmt(sampler),
                'outer_tail':fmt(tau),'NE_loss':fmt(ne),'SH_loss':fmt(sh),
                'solver_lower_bound':fmt(lower),'UF_comparison_raw':f'{upper:.12E}',
                'UF_comparison_capped':f'{min(Decimal(1),upper):.12E}',
                'vacuous_comparison':upper>=1,'positive_solver_lower_bound':lower>0,
                'inner_sampler_calls_UF':issuance,'ordinary_slots_Q':queries,
                'challenge_samples_UF_max':issuance+2*queries,
                'outer_scalar_calls':1 if kind=='PS' else n+1,
                'inner_sampler_calls_NE_max':2+2*exposure*L,
                'modes':'ECQV and PV; same probability formula, different operation costs'}


def main():
    rows=[]
    for kind in ('PS','Waters'):
        for hb in (20,32,64,128):
            rows.append(evaluate(kind,h=2**hb))
        rows.append(evaluate(kind,k=32,outer=32))
        rows.append(evaluate(kind,lam=64,h=2**64))
    assert evaluate('PS',issuance=0,exposure=0)['issuance_loss']=='0.000000000000E+12'
    assert not evaluate('PS')['vacuous_comparison']
    assert evaluate('Waters',lam=64,h=2**64)['vacuous_comparison']
    assert Decimal(evaluate('PS')['issuance_loss']) < Decimal(evaluate('Waters')['issuance_loss'])
    assert Decimal(evaluate('PS',k=32,outer=32)['solver_lower_bound'])==0
    root=Path(__file__).parent
    (root/'finite_bounds.json').write_text(json.dumps({'q':str(QORDER),
        'scope':'fixed finite B, conditional scenario gamma; no measured OW hardness or security-bit claim',
        'rows':rows},indent=2),encoding='utf-8')
    with (root/'finite_bounds.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(json.dumps({'rows':len(rows),'formula_checks':5,'default':rows[1]}))


if __name__=='__main__':
    main()
