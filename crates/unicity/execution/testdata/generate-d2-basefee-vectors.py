import json
MAX=(1<<62)
def calc(parent,used,capacity,floor=7,elasticity=2,denom=8):
    target=capacity//elasticity
    delta=parent*abs(used-target)//target//denom
    nxt=parent+max(1,delta) if used>target else parent-delta if used<target else parent
    return min(MAX,max(floor,nxt))
cases=[]
for parent in [7,8,1000000000,10**13,MAX]:
 for used in [0,1,14000000,14000001,28000000]:
  cases.append(dict(parentBaseFee=parent,ordinaryGasUsed=used,ordinaryCapacity=28000000,baseFeeFloor=7,elasticity=2,changeDenominator=8,nextBaseFee=calc(parent,used,28000000)))
print(json.dumps({'source':'independent Python integer implementation of accepted D2 formula; example profile, not a deployment choice','maxBaseFee':MAX,'vectors':cases},indent=2))
