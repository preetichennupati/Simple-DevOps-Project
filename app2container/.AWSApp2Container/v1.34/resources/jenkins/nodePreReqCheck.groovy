import hudson.util.RemotingDiagnostics;
import jenkins.model.Jenkins;

String agent_name = '<node>';

groovy_script = '''
println \"aws --version\".execute().text
println \"docker --version\".execute().text
println \"git --version\".execute().text
'''.trim();

String result;
Jenkins.instance.nodes.find { agent ->
    agent.name == agent_name
}.with { agent ->
    result = RemotingDiagnostics.executeGroovy(groovy_script, agent.channel)
};
return result;