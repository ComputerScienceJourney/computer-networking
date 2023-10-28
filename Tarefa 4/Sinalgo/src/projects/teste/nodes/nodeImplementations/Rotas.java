package projects.teste.nodes.nodeImplementations;

import java.text.DecimalFormat;
import java.util.ArrayList;

public class Rotas{
    ArrayList<SimpleNode> Rota;
    Double custo;
    
    public Rotas(){
        Rota=new ArrayList<SimpleNode>();
    }
    
    public void calccusto(){
        /*custo=0.0;
        for(int i=0;i<Rota.size()-1;i++){
            for(int j=0;j<Rota.get(i).Neighbors.size();j++){
                if(Rota.get(i).Neighbors.get(j)==Rota.get(i+1)){
                    custo+=(Double) Rota.get(i).Neighborscost.get(j);
                }
            }
        }*/
        custo = (Rota.size()-1)*5.0;
    }
    
    public Double getcustototal(){
        calccusto();
        return custo;
    }
    
    public void add(SimpleNode n){
        Rota.add(n);
    }
    
    public void rem(int i){
        Rota.remove(i);
    }
    
    public void remlim(int n, int n2){
        for(int i=n;i<n2;i++){
            Rota.remove(n);
        }
    }
    
    public void remult(){
        Rota.remove(Rota.size()-1);
    }
    
    public SimpleNode getorigem(){
        return Rota.get(0);
    }
    
    public SimpleNode getdestino(){
        return Rota.get(Rota.size()-1);
    }
    
    public int getIdDestino(){
        return Rota.get(Rota.size()-1).ID;
    }
    
    public SimpleNode getpos(int n){
        return Rota.get(n);
    }
    
    public Object getrota(){
        return Rota;
    }
    public int getsize(){
        return Rota.size();
    }
    
    public void limpa(){
        Rota.clear();
    }
    
    public void setcusto(Double c){
        custo=c;
    }
    
    public SimpleNode getnext(SimpleNode At){
        SimpleNode R=null;
        for(int i=0;i<Rota.size()-1;i++){
            R=Rota.get(i);
            if(R.equals(At)){
                R=Rota.get(i+1);
                break;
            }
        }
        return R;
    }
    
    public String tostr(){
        String S="";
        for (SimpleNode Rota1 : Rota) {
            S += "-" + Rota1.ID;
        }
        calccusto();
        S+="="+new DecimalFormat("0.00").format(custo);
        return S;
    }
    
    public void copy(Rotas D){
        for (SimpleNode Rota1 : Rota) {
            D.add(Rota1);
        }
        D.setcusto(custo);
    }
    
    public void copy(Rotas D, int n){
        for (int i=0;i<Rota.size()-n;i++) {
            D.add((SimpleNode) this.getpos(i));
        }
        D.calccusto();
    }
    
    public boolean verifica(){
        boolean b=true;
        SimpleNode R1;
        for(int i=0;i<this.getsize()-1;i++){
            R1=(SimpleNode) getpos(i);
            if(R1.Neighbors.contains(getpos(i+1))){
                b=false;
            }
        }
        return b;
    }
    
    public void EliminaLoops(){
        int b=0;
        for(int n=0;n<getsize();n++){
            for(int i=n+1;i<getsize();i++){
                 if(getpos(i).equals(getpos(n))){
                    remlim(n,i);
                    b=1;
                }
            }
        }
        if(b==1){
            EliminaLoops();
        }
        if(verifica()){
            calccusto();
        }
    }
}
