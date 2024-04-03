import hudson.util.RemotingDiagnostics;
import jenkins.model.Jenkins;

String agent_name = '<node>';
def groovy_script = """
"powershell (gp 'HKLM:\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows NT\\\\\\\\CurrentVersion').ReleaseId".execute().text
"""

String result;
Jenkins.instance.nodes.find { agent ->
    agent.name == agent_name
}.with { agent ->
    result = RemotingDiagnostics.executeGroovy(groovy_script, agent.channel);
};
println result;