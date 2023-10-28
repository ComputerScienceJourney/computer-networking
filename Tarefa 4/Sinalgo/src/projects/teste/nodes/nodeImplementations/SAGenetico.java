package projects.teste.nodes.nodeImplementations;

import java.util.Random;
import javax.swing.JOptionPane;
import projects.teste.nodes.messages.testemsg;

public class SAGenetico {
    SimpleNode Origem;
    SimpleNode Destino;
    TabelaRotas População;
    int Gerações;
    int individuos;
    Rotas vet[];
    double vetcusto[];
    double vetprob[];
    double C_Mutação,C_Cruzamento;
    int SA_individuos;
    
    
    public SAGenetico(){
        
    }

    public SAGenetico(TabelaRotas População, int Gerações, double C_Mut, double C_Crz, int SA_ind) {
        this.População = População;
        this.Gerações=Gerações;
        individuos=População.getsize()+SA_individuos;
        vet=new Rotas[individuos];
        vetcusto=new double[individuos];
        vetprob=new double[individuos];
        C_Mutação=C_Mut;
        C_Cruzamento=C_Crz;
        SA_individuos = SA_ind;
        for(int i=0;i<individuos;i++){
            vet[i]=(Rotas) População.getrotaindex(i);
            vetcusto[i]=vet[i].getcustototal();
        }
    }
    
    public double[] Evoluir(){
        //System.out.println("SGA evolving");
        double v[] = new double[Gerações];
        int Lim=Gerações;
        int c=0,b=0;
        Random E=new Random();
        for(int i=0;i<SA_individuos;i++){
            SimulatedAnnealing SA = new SimulatedAnnealing(vet[i], 1000.0, 50, 0.9, 4, 4);
            SA.Evoluir();
            vet[individuos-SA_individuos+i] = SA.getRota();
            vetcusto[individuos-SA_individuos+i]= SA.getRotaCusto();
        }
        for(int i=0;i<Gerações;i++){
            ordena();
            v[i]=vet[0].getcustototal();
            calcvetprob();
            for(int j=0;j<individuos-1;j++){
                seleciona(j);
                muta(j);
            }
            b=0;
            for(int k=0;k<individuos;k++){
                for(int l=0;l<individuos;l++){
                    if(vetcusto[l] != vetcusto[k]){
                        b=1;
                        break;
                    }
                }
                if(b==1){
                    break;
                }
            }
            if(b==0){
                //System.out.println("break! "+i);
                break;
            }
        }
        ordena();
        return v;
    }
    
     public void quick_sort(double []v,int ini, int fim) {
        int meio;
        if (ini < fim) {
            meio = partition(v, ini, fim);
            quick_sort(v, ini, meio);
            quick_sort(v, meio + 1, fim);
        }
    }
 
    public int partition(double []v, int ini, int fim) {
        double pivo;
        int topo, i;
        pivo = v[ini];
        topo = ini;

        for (i = ini + 1; i <= fim; i++) {
              if (v[i] < pivo) {
                v[topo] = v[i];
                vet[topo]=vet[i];
                v[i] = v[topo + 1];
                vet[i]=vet[topo+1];
                topo++;
              }
        }
        v[topo] = pivo;
        return topo;
    }
    
    public void ordena(){
        quick_sort(vetcusto,0, individuos-1);
    }
    
    public void calcvetprob(){
        double custoTotal=0.0;
        for(int i=0;i<vet.length;i++){
            custoTotal+=vetcusto[i];
        }
        for(int i=0;i<vet.length;i++){
            vetprob[i]=vetcusto[i]/custoTotal;
        }
    }
    
    public void seleciona(int pai1){
        Random E=new Random();
        double A;
        A=E.nextDouble();
        double sel=0.0;
        int pai2=-1;
        while(sel<A){
            pai2++;
            sel += vetprob[pai2];
        }
        cruza(pai1, pai2);
    }
    
    public void cruza(int pai1, int pai2){
        Random E=new Random();
        double A;
        A=E.nextDouble();
        if(A<C_Cruzamento){
            int a=0,b=0;
            for(int i=0;i<vet[pai1].getsize();i++){
                for(int j=0;j<vet[pai2].getsize();j++){
                    if(vet[pai1].getpos(i)==vet[pai2].getpos(j)){
                        a=i;
                        b=j;
                    }
                }
            }
            Rotas filho=new Rotas();
            for(int i=0;i<a;i++){
                filho.add((SimpleNode) vet[pai1].getpos(i));
            }
            for(int i=b;i<vet[pai2].getsize();i++){
                filho.add((SimpleNode) vet[pai2].getpos(i));
            }
            for(int i=0;i<População.getsize();i++){
                if(População.getrotaindex(i)==filho){
                    filho=(Rotas) População.getrotaindex(i);
                }
            }
            filho.calccusto();
            if(vet[pai1].getcustototal()>vet[pai2].getcustototal()){
                if(vet[pai1].getcustototal()>filho.getcustototal()){
                    vet[pai1]=filho;
                    vetcusto[pai1]=filho.getcustototal();
                }
            }
            else{
                if(vet[pai2].getcustototal()>vet[pai1].getcustototal()){
                    if(vet[pai2].getcustototal()>filho.getcustototal()){
                        vet[pai2]=filho;
                        vetcusto[pai2]=filho.getcustototal();
                    }
                }
            }
        }
    }
    
    public void muta(int cromossomo){
        int b=0;
        Random E=new Random();
        double A;
        A=E.nextDouble();
        if(A<C_Mutação){
            Rotas nrota=new Rotas();
            for(int n=0;n<vet[cromossomo].getsize();n++){
                SimpleNode O = (SimpleNode) vet[cromossomo].getpos(n);
                for(int i=n+2;i<vet[cromossomo].getsize();i++){
                     if(O.Neighbors.contains(vet[cromossomo].getpos(i))){
                        for(int k=0;k<=n;k++){
                            nrota.add((SimpleNode) vet[cromossomo].getpos(k));
                        }
                        for(int j=i;j<(vet[cromossomo].getsize());j++){
                            nrota.add((SimpleNode) vet[cromossomo].getpos(j));                    
                        }
                        nrota.calccusto();
                        if(nrota.custo<vet[cromossomo].custo){
                            vet[cromossomo]=nrota;
                        }
                        b=1;
                        break;
                    }
                }
                if(b==1){
                    break;
                }
            }
        }
    }
    
    public int getmedia(){
        int media=0;
        for(int i=0;i<População.getsize();i++){
            media+=vet[i].getcustototal();
        }
        media=media/População.getsize();
        return media;
    }
    
    public String getrotas(){
        String s="";
        s+="\n";
        for(int i=0;i<individuos;i++){
            s+=vet[i].tostr();
            s+="\n";
        }
        return s;
    }
    
    public Rotas getRota(){
        return vet[0];
    }
        
    public String getSRota(){
        String s="";
        s+="\n";
        s+=vet[0].tostr();
        return s;
    }
}