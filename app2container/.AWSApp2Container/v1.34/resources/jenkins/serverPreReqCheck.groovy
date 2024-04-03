import hudson.util.RemotingDiagnostics;
import jenkins.model.Jenkins;

groovy_script = '''
println \"git --version\".execute().text
'''.trim();

String result;

result = RemotingDiagnostics.executeGroovy(groovy_script, Jenkins.instance.channel)
println result;