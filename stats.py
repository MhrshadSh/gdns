from scamper import ScamperCtrl

ctrl = ScamperCtrl(mux="/run/ark/mux")
# Select only DNS-capable vantage points
vps = [vp for vp in ctrl.vps() if 'primitive:dns' in vp.tags]

vp_cc = []
vp_asn = []
vp_st = []


for vp in vps:
    vp_cc.append(vp.cc)
    vp_asn.append(vp.asn4)
    vp_st.append(vp.st)

print(vp_st)

print(f"number of vps: {len(vps)}\n\
      unique countries: {len(set(vp_cc))}\n\
        unique state: {len(set(vp_st))}\n\
        unique ASN: {len(set(vp_asn))}")