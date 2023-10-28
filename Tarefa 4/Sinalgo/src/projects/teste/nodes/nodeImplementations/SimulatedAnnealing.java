/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package projects.teste.nodes.nodeImplementations;

import java.util.Random;

/**
 *
 * @author danielfonseca
 */
public class SimulatedAnnealing {
    Rotas best_solution;
    Rotas solucao;
    Double temperature;
    int max_iterations;
    Double alfa;
    int L;
    int P;
    public SimulatedAnnealing(
            Rotas solucao,
            Double initial_temp,
            int max_iter,
            Double alfa,
            int max_success,
            int max_pert){
        this.best_solution=solucao;
        this.solucao=solucao;
        this.temperature = initial_temp;
        this.max_iterations = max_iter;
        this.alfa = alfa;
        this.L = max_success;
        this.P = max_pert;
    }
    
    public void Evoluir(){
        //System.out.println("SA evolving");
        int j=0;
        while(true){
            int i=1;
            int nsucesso = 0;
            while(true){
                Rotas nsolucao=muta(solucao);
                Double delta = nsolucao.getcustototal() - solucao.getcustototal();
                if(delta<0){
                    best_solution = nsolucao;
                    solucao = nsolucao;
                    nsucesso++;
                }
                i++;
                if(nsucesso>=L || i>P){
                    break;
                }
            }
            temperature=alfa*temperature;
            j++;
            if(j<max_iterations){
                break;
            }
        }
    }
    
    public Rotas muta(Rotas solucao){
        Rotas nrota=new Rotas();
        for(int n=0;n<solucao.getsize();n++){
            SimpleNode O = (SimpleNode) solucao.getpos(n);
            for(int i=n+2;i<solucao.getsize();i++){
                if(O.Neighbors.contains(solucao.getpos(i))){
                    for(int k=0;k<=n;k++){
                        nrota.add((SimpleNode) solucao.getpos(k));
                    }
                    for(int j=i;j<(solucao.getsize());j++){
                        nrota.add((SimpleNode) solucao.getpos(j));                    
                    }
                    nrota.calccusto();
                    return nrota;
                }
            }
        }
        return solucao;
    }
    
    public Rotas getRota(){
        return this.solucao;
    }
    
    public Double getRotaCusto(){
        return this.solucao.custo;
    }
}

