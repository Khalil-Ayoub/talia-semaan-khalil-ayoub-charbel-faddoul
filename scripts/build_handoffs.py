"""Generate described Postman requests and reproducible clean delivery ZIPs."""
import json
import shutil
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')


def postman():
    folders = []
    samples = {
        'assets': dict(asset_name='Lab Server',asset_type='Server',ip_address='192.0.2.10',department='IT',owner_id='{{owner_id}}',criticality_level='High'),
        'threats': dict(threat_type='Domain',threat_value='example.test',description='Training indicator',severity='High',source='Local exercise'),
        'vulnerabilities': dict(title='Training finding',description='Lab only',cve_identifier='CVE-2026-12345',cvss_score=8.1,severity='High',asset_id='{{asset_id}}',discovery_source='Local exercise')
    }

    def item(service,name,method,path='',payload=None,token='admin_token',expected=200,description='',save=None,query=''):
        variable = {'assets':'assets_url','threats':'threats_url','vulnerabilities':'vulnerabilities_url'}[service]
        request = {'method':method,'header':[], 'url':'{{'+variable+'}}/{{owner_prefix}}/'+service+path+query,
                   'description':description+' Expected HTTP '+str(expected)+'. Actual responses must be captured from the running integrated system.'}
        if token:
            request['header'].append({'key':'Authorization','value':'Bearer {{'+token+'}}','type':'text'})
        if payload is not None:
            raw = json.dumps(payload,indent=2)
            for variable_name in ('owner_id','asset_id'):
                raw = raw.replace('"{{'+variable_name+'}}"','{{'+variable_name+'}}')
            request['header'].append({'key':'Content-Type','value':'application/json','type':'text'})
            request['body']={'mode':'raw','raw':raw,'options':{'raw':{'language':'json'}}}
        lines = [f"pm.test('HTTP {expected}', function () {{ pm.response.to.have.status({expected}); }});"]
        if save:
            lines.append(f"if (pm.response.code === {expected}) pm.environment.set('{save}', pm.response.json().data.id);")
        return {'name':name,'request':request,'response':[], 'event':[{'listen':'test','script':{'type':'text/javascript','exec':lines}}]}

    for service,sample in samples.items():
        idvar = {'assets':'asset_id','threats':'threat_id','vulnerabilities':'vulnerability_id'}[service]
        path = '/{{'+idvar+'}}'
        update = {'assets':{'status':'Under Maintenance'},'threats':{'severity':'Critical'},'vulnerabilities':{'status':'Under Investigation'}}[service]
        search = {'assets':'?department=IT&criticality_level=High','threats':'?threat_type=Domain&source=Local','vulnerabilities':'?asset_id={{asset_id}}&severity=High'}[service]
        requests = [
            item(service,'01 Create','POST',payload=sample,expected=201,save=idvar,description='Create an actual sample record and save its ID. Use a real existing owner; create asset before vulnerability.'),
            item(service,'02 List','GET',description='Retrieve all stored records; compare returned array with database.'),
            item(service,'03 Detail','GET',path,description='Retrieve existing record.'),
            item(service,'04 Missing ID','GET','/2147483647',expected=404,description='Verify unused nonexistent ID before running.'),
            item(service,'05 Search','GET','/search',query=search,description='Demonstrate combined filters; also execute each documented filter separately.'),
            item(service,'06 Update','PUT',path,update,description='Capture DB before and after. Vulnerability must currently be Open.'),
            item(service,'07 Auditor read','GET',path,token='auditor_token',description='Auditor can read records.'),
            item(service,'08 Employee denied','GET',path,token='employee_token',expected=403,description='Same resource is forbidden to employee; verify automatic audit record.'),
            item(service,'09 No token','GET',path,token=None,expected=401,description='Request without authentication.'),
            item(service,'10 Invalid token','GET',path,token='invalid_token',expected=401,description='Invalid token rejected by real identity service.'),
            item(service,'11 Empty body','POST',payload={},expected=400,description='Required field validation.'),
            item(service,'12 Auditor update denied','PUT',path,update,token='auditor_token',expected=403,description='Read-only role cannot modify.'),
            item(service,'13 Analyst delete denied','DELETE',path,token='analyst_token',expected=403,description='Analyst cannot delete.'),
        ]
        if service == 'assets':
            requests.append(item(service,'Asset history','GET',path+'/history',description='Inspect create/update snapshots, acting user and timestamps.'))
            bad = dict(sample,ip_address='999.1.1.1')
            requests.append(item(service,'Invalid IP','POST',payload=bad,expected=400,description='Reject malformed IP.'))
            requests.append(item(service,'Analyst scoped search','GET','/search',token='analyst_token',query='?department=IT',description='Only assigned-incident assets appear. Set up incident and analyst assignment through Part 3.'))
        elif service == 'threats':
            requests.append(item(service,'Duplicate indicator','POST',payload=sample,expected=409,description='Execute after creation and before deletion; duplicate type/value rejected.'))
            requests.append(item(service,'Invalid file hash','POST',payload=dict(sample,threat_type='File Hash',threat_value='bad'),expected=400,description='Reject nonhex/wrong-length hash.'))
        else:
            requests.append(item(service,'Invalid CVSS','POST',payload=dict(sample,cvss_score=11),expected=400,description='Score outside 0..10 rejected.'))
            requests.append(item(service,'Skipped transition','PUT',path,{'status':'Closed'},expected=400,description='Run before reaching Resolved: skipped lifecycle transition rejected.'))
            for status in ('In Progress','Resolved','Closed'):
                requests.append(item(service,'Progress '+status,'PUT',path,{'status':status},token='analyst_token',description='Continue from Under Investigation in order; verify generated resolution date.'))
        folders.append({'name':service.title(),'description':'Use fresh data and execute dependencies in order; see API reference and evidence checklist.','item':requests})

    destructive = []
    for service in ('vulnerabilities','threats','assets'):
        idvar = {'assets':'asset_id','threats':'threat_id','vulnerabilities':'vulnerability_id'}[service]
        destructive.append(item(service,'Delete '+service,'DELETE','/{{'+idvar+'}}',description='Destructive. Run after screenshots. Delete vulnerability before its asset; incident references can still prevent asset deletion.'))
    folders.append({'name':'Run last - authorized deletions','item':destructive})
    write_json(ROOT/'postman/part1.collection.json',{'info':{'name':'Sprint 1 Part 1 Assets Threats Vulnerabilities','schema':'https://schema.getpostman.com/json/collection/v2.1.0/collection.json','description':'Development requests, not execution evidence. Set exact owner prefix, real account IDs and real tokens. Dependencies are required.'},'item':folders})
    variables = {'assets_url':'http://127.0.0.1:5002','threats_url':'http://127.0.0.1:5004','vulnerabilities_url':'http://127.0.0.1:5007','owner_prefix':'khalil-ayoub','owner_id':'','asset_id':'','threat_id':'','vulnerability_id':'','admin_token':'','analyst_token':'','auditor_token':'','employee_token':'','invalid_token':'deliberately-invalid'}
    write_json(ROOT/'postman/part1.environment.json',{'name':'Sprint 1 Part 1 local','values':[{'key':k,'value':v,'enabled':True,'type':'secret' if 'token' in k else 'default'} for k,v in variables.items()], '_postman_variable_scope':'environment'})


def archive(name, paths):
    destination = ROOT/'deliveries'/name
    destination.parent.mkdir(exist_ok=True)
    with ZipFile(destination,'w',ZIP_DEFLATED) as z:
        for relative in paths:
            path = ROOT/relative
            candidates = path.rglob('*') if path.is_dir() else [path]
            for candidate in candidates:
                if candidate.is_file() and '__pycache__' not in candidate.parts and candidate.suffix != '.pyc':
                    z.write(candidate,candidate.relative_to(ROOT).as_posix())


if __name__ == '__main__':
    postman()
    package = ROOT/'deliveries'/'final-package'
    package.mkdir(parents=True, exist_ok=True)
    shared = ['common','team_config.json','repository.json','TEAM_CONTRACT.md','requirements.txt','.gitignore','README.md','prompts','scripts/build_handoffs.py']
    for relative in shared:
        source, destination = ROOT/relative, package/relative
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    archive('final-package/khalil ayoub.zip', ['part1','tests/__init__.py','tests/test_part1.py','postman/part1.collection.json','postman/part1.environment.json','docs/part1'])
    for part, name, services, prompt in [
        ('part2','talia semaan','Users, Logging, Notifications','COLLEAGUE_1.md'),
        ('part3','charbel faddoul','Incidents, Reports, Playbooks','COLLEAGUE_2.md')]:
        owned = [part, f'docs/{part}', f'postman/{part}.collection.json', f'postman/{part}.environment.json', f'tests/test_{part}.py']
        if (ROOT/part/'app.py').is_file():
            archive('final-package/'+name+'.zip', [p for p in owned if (ROOT/p).exists()])
        else:
            with ZipFile(package/(name+'.zip'),'w',ZIP_DEFLATED) as z:
                z.writestr(part+'/DELIVERY_PENDING.md', f'# {name.title()} delivery pending\n\nAssigned services: {services}.\nThis ZIP currently contains handoff instructions only; the services have not been delivered.\nRead the external TEAM_CONTRACT.md and prompts/{prompt}, then replace this ZIP with your completed delivery named exactly `{name}.zip`.\nExtract all three personal ZIPs into the same folder as the external common/ folder before running.\n')
    print('Generated deliveries/final-package: three personal ZIPs plus external shared files. Colleague ZIPs are pending-delivery handoffs.')
