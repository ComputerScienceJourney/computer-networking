package projects.teste.nodes.nodeImplementations;


import java.util.ArrayList;
import java.util.Random;

public class TabelaRotas {
    ArrayList<Rotas> Rotas;
    String ID;
    
    public TabelaRotas(String ID) {
        Rotas=new ArrayList<Rotas>();
        this.ID=ID;
    }
    
    public void addrota(Rotas R){
        Rotas.add(R);
    }
    
    public int getsize(){
        return Rotas.size();
    }
    
    public Object getrota(int num, int destino){
        TabelaRotas P=new TabelaRotas("Tab");
        TabelaRotas R=new TabelaRotas("Tab");
        for (Rotas Rota : Rotas) {
            SimpleNode S=(SimpleNode) Rota.getdestino();
            if (S.ID == destino) {
                P.addrota(Rota);
            }
        }
        if(num!=0){
            for(int i=0;i<num;i++){
                R.addrota((Rotas) P.getAnyRota(destino));
            }
        }
        else{
            R=P;
        }
        return R;
        
    }
    
    public Object getAnyRota(int destino){
        Random E=new Random();
        TabelaRotas P=new TabelaRotas("Tab");
        P=(TabelaRotas) this.getrota(0, destino);
        return P.getrotaindex(E.nextInt(P.getsize()));
    }
        
    public Object getrotaindex(int i){
        return Rotas.get(i);
    }
    
    public void limpa(){
        Rotas.clear();
    }
    
    public void delrotas(int destino){
        ArrayList O=(ArrayList) getrota(0, destino);
        for (Object O1 : O) {
            Rotas.remove(O1);
        }
    }
    
    public int getnumdestino(int destino){
        int num=0;
        SimpleNode R;
        if(Rotas.size()>0){
            for(int i=0;i<Rotas.size();i++){
                R=(SimpleNode) Rotas.get(i).getdestino();
                if(R.ID==destino){
                    num++;
                }
            }
        }
        return num;
    }
        
    public String tostring(){
        String Str="\n \n Tabela de rotas Roteador "+ ID;
        for (Rotas Rota : Rotas) {
            Str += "\n" + Rota.tostr();
        }
        return Str;
    }
}
