package projects.teste.nodes.timers;

import projects.teste.nodes.messages.testemsg;
import projects.teste.nodes.nodeImplementations.SimpleNode;
import sinalgo.nodes.Node;
import sinalgo.nodes.timers.Timer;

public class timerSG extends Timer {
    
    public timerSG(){
    }
    
    @Override
    public void fire() {
        ((SimpleNode)node).PreencheTabSG();
    }
}