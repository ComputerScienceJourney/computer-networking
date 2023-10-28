package projects.teste.nodes.messages;

import projects.teste.nodes.nodeImplementations.Rotas;
import sinalgo.nodes.Node;
import sinalgo.nodes.messages.Message;

public class testemsg extends Message{
    long tempoInicio,tempoFim;
    public Rotas R;
    public String alg;
    
    //Construtor da Classe
    public testemsg(Rotas Rota, long T, String alg){
        tempoInicio= T;
        this.R=Rota;
        this.alg = alg;
    }
    
    public long getTempoInicio() {
        return tempoInicio;
    }

    public void setTempoInicio(long tempoInicio) {
        this.tempoInicio = tempoInicio;
    }

    public long getTempoFim() {
        return tempoFim;
    }

    public void setTempoFim(long tempoFim) {
        this.tempoFim = tempoFim;
    }
    
    public long calcTempoTotal(){
        return tempoFim-tempoInicio;
    }
    
    @Override
    public Message clone() {
        testemsg msg = new testemsg(this.R,this.tempoInicio, this.alg);
        msg.tempoInicio=this.tempoInicio;
        return msg;
    }
}
