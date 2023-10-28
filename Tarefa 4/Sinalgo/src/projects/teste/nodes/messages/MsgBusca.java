/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package projects.teste.nodes.messages;

import projects.teste.nodes.nodeImplementations.Rotas;
import projects.teste.nodes.nodeImplementations.SimpleNode;
import sinalgo.nodes.messages.Message;

/**
 *
 * @author Daniel
 */
public class MsgBusca extends Message{
    public SimpleNode Origem; 
    int IDDestino;
    public Rotas R;
    long TempoInicio;
    public int count;
    
    public MsgBusca(SimpleNode Origem,int Destino,long T){
        this.IDDestino = Destino;
        this.R=new Rotas();
        this.R.add(Origem);
        this.TempoInicio=T;
    }
    
    public MsgBusca(Rotas R,int Destino,long T){
        this.R=R;
        this.IDDestino=Destino;
        this.TempoInicio=T;
    }
    
    public void add(SimpleNode pos){
        this.R.add(pos);
        count++;
        if(count == 50){
            R.EliminaLoops();
            count =0;
        }
    }

    public long getTempoInicio() {
        return TempoInicio;
    }

    public void setTempoInicio(long TempoInicio) {
        this.TempoInicio = TempoInicio;
    }
    
    @Override
    public Message clone() {
        MsgBusca msg = new MsgBusca(this.R,IDDestino,TempoInicio);
        return msg;
    }

    public SimpleNode getOrigem() {
        return Origem;
    }

    public void setOrigem(SimpleNode Origem) {
        this.Origem = Origem;
    }

    public int getIDDestino() {
        return IDDestino;
    }

    public void setIDDestino(int IDDestino) {
        this.IDDestino = IDDestino;
    }

    public Rotas getR() {
        return R;
    }

    public void setR(Rotas R) {
        this.R = R;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }
    
}
