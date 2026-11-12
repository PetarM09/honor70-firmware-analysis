#!/usr/bin/env python3
"""Compare GPL source ABI drift, without deriving runtime GhostLock offsets.

Inputs are GitHub Actions artifacts containing extracted GPL source files.
This is offline only; not an exploit builder or a substitute for exact-C431 ABI.
"""
import argparse,hashlib,json,re,zipfile
from pathlib import Path
ROLES=('include_sched_h','kernel_rtmutex_common_h','kernel_makefile','merge_lahaina_defconfig')
OPTIONS=('CONFIG_HN_VIP_THREAD','CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT',
         'CONFIG_HN_SET_ASYNC_BINDER_RT','CONFIG_FUTEX_PI',
         'CONFIG_RT_MUTEXES','CONFIG_DEBUG_RT_MUTEXES')
FIELDS={
'vip_last_queued':r'\bu64\s+hn_vip_last_queued\s*;',
'pi_lock':r'\braw_spinlock_t\s+pi_lock\s*;',
'pi_blocked_on':r'\bstruct\s+rt_mutex_waiter\s*\*\s*pi_blocked_on\s*;',
'real_cred':r'\bconst\s+struct\s+cred\s+__rcu\s*\*\s*real_cred\s*;',
'cred':r'\bconst\s+struct\s+cred\s+__rcu\s*\*\s*cred\s*;',
'binder_recovery':r'\bbool\s+need_next_recovery\s*;'
}
def get_files(archive, folder):
    result={}
    with zipfile.ZipFile(archive) as z:
        names=set(z.namelist())
        for role in ROLES:
            path=f'{folder}/{role}.txt'
            if path not in names:raise ValueError('Missing source '+path)
            data=z.read(path)
            result[role]={'text':data.decode('utf-8'),
                          'sha256':hashlib.sha256(data).hexdigest()}
    return result

def option_value(text,key):
    found=set(re.findall(r'^\s*'+re.escape(key)+r'=(y|m|n)\s*$',text,re.M))
    if re.search(r'^\s*#\s*'+re.escape(key)+r'\s+is\s+not\s+set\s*$',text,re.M):
        found.add('n')
    return 'conflicting' if len(found)>1 else (next(iter(found)) if found else 'not_listed')

def positions(text):
    at=text.find('struct task_struct {')
    if at<0:raise ValueError('Missing task_struct anchor')
    tail=text[at:]
    result={}
    for key,pattern in FIELDS.items():
        m=re.search(pattern,tail)
        result[key]={'line':text[:at].count('\n')+tail[:m.start()].count('\n')+1 if m else None}
    return result

def audit(old,new):
    if not all(role in item for item in (old,new) for role in ROLES):
        raise ValueError('Incomplete source bundle')
    o=positions(old['include_sched_h']['text'])
    n=positions(new['include_sched_h']['text'])
    oldconf={k:option_value(old['merge_lahaina_defconfig']['text'],k) for k in OPTIONS}
    newconf={k:option_value(new['merge_lahaina_defconfig']['text'],k) for k in OPTIONS}
    pos=n['vip_last_queued']['line']
    early=pos is not None and all(n[k]['line'] is not None and pos<n[k]['line']
        for k in ('pi_lock','pi_blocked_on','real_cred','cred'))
    return {
      'schema_version':1,
      'baseline':'HONOR FNE-AN00 MagicUI6.1 GPL (Makefile 5.4.147)',
      'comparison':'HONOR 70 Fennie MagicOS8 GPL (Makefile 5.4.242)',
      'target_running_kernel':'5.4.295-qgki-ga2d8945339ca',
      'comparison_is_exact_running_C431':False,
      'source_hashes':{
         'an00_sched':old['include_sched_h']['sha256'],
         'fennie_sched':new['include_sched_h']['sha256'],
         'an00_waiter':old['kernel_rtmutex_common_h']['sha256'],
         'fennie_waiter':new['kernel_rtmutex_common_h']['sha256']},
      'published_waiter_definition_identical':
         old['kernel_rtmutex_common_h']['sha256']==new['kernel_rtmutex_common_h']['sha256'],
      'an00_source_struct_field_positions':o,
      'fennie_source_struct_field_positions':n,
      'an00_merged_vendor_config_flags':oldconf,
      'fennie_merged_vendor_config_flags':newconf,
      'fennie_vip_field_before_pi_and_creds':early,
      'source_level_struct_layout_drift_risk':
         'supported' if early and
            newconf['CONFIG_HN_VIP_THREAD']=='y' and
            newconf['CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT']=='y' and
            oldconf['CONFIG_HN_VIP_RUNNABLE_TIME_LIMIT']=='n'
            else 'inconclusive',
      'effect_on_real_C431_field_offsets':'not_established',
      'runtime_compilation_options_of_real_phone':'not_measured_here',
      'device_operations':0,
      'ghostlock_profile_ready':False,
      'interpretation':'A conditional field precedes PI and cred in the newer published GPL source. No numeric field offsets were inferred.'
    }

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--an00-artifact',type=Path,required=True)
    p.add_argument('--fennie-artifact',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=audit(get_files(a.an00_artifact,'AN00'),get_files(a.fennie_artifact,'FENNIE'))
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('WAITERS_SAME_IN_PUBLISHED_SOURCES',result['published_waiter_definition_identical'])
    print('SOURCE_LEVEL_STRUCT_DRIFT',result['source_level_struct_layout_drift_risk'])
    print('EXACT_C431_LAYOUT_VALIDATED',False)
