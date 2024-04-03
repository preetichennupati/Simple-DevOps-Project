import hudson.util.RemotingDiagnostics;
import jenkins.model.Jenkins;

String agent_name = '<node>';

def groovy_script = """
def command = [
'powershell', '-command',
'if(!(Test-Path \"\$env:USERPROFILE\\\\\\\\.ssh\\\\\\\\config\")){echo \"notfound\"}'];
command.execute().text
"""

String result;
Jenkins.instance.nodes.find { agent ->
    agent.name == agent_name
}.with { agent ->
    result = RemotingDiagnostics.executeGroovy(groovy_script, agent.channel)
};
return result;