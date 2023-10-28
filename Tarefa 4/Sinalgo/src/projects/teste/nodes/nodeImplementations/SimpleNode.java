package projects.teste.nodes.nodeImplementations;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Random;
import javax.swing.JOptionPane;
import projects.teste.nodes.messages.MsgBusca;
import projects.teste.nodes.messages.MsgBuscaSA;
import projects.teste.nodes.messages.MsgBuscaSG;
import projects.teste.nodes.messages.testemsg;
import projects.teste.nodes.timers.timerP;
import projects.teste.nodes.timers.timerS;
import projects.teste.nodes.timers.timerSG;
import sinalgo.configuration.WrongConfigurationException;
import sinalgo.nodes.edges.Edge;
import sinalgo.nodes.messages.Inbox;
import sinalgo.nodes.messages.Message;
import sinalgo.tools.storage.ReusableListIterator;

public class SimpleNode extends sinalgo.nodes.Node {
    int Destino = 119;
    ArrayList<SimpleNode> Neighbors = new ArrayList<>();
    ArrayList<Double> Neighborscost = new ArrayList<>();
    TabelaRotas Tab = new TabelaRotas("Tab");
    int PopulaçãoGA = 30;
    int PopulaçãoSGA = 10;
    int Geracoes = 30;
    int execucoes=30,contador=0;
    double M[][] = new double[execucoes][Geracoes];
    double  V[] = new double[Geracoes];
    

    public void findNeighbors() {
        
        Random R = new Random();
        Edge e;
        ReusableListIterator<Edge> i = outgoingConnections.iterator();
        while (i.hasNext()) {
            e = i.next();
            if (!(Neighbors.contains(e.endNode))) {
                Neighbors.add((SimpleNode) e.endNode);
                Neighborscost.add(5.0);
            }
        }
    }

    @Override
    public void handleMessages(Inbox inbox) {
        while (inbox.hasNext()) {
            Message message = inbox.next();
            if (message instanceof testemsg) {
                testemsg TMessage = (testemsg) message;
                if (TMessage.R.getIdDestino() != ID) {
                    send(TMessage, TMessage.R.getnext(this));
                } else {
                    Double CustoA = TMessage.R.getcustototal();
                    Double CustoB = (System.currentTimeMillis() - TMessage.getTempoInicio()) / 1000.0;
                    System.out.println(new DecimalFormat("0.00").format(CustoA) + "  " + new DecimalFormat("0.00").format(CustoB) + "  " + new DecimalFormat("0.00").format(CustoA + CustoB));
                    TMessage.R.getorigem().Tab.limpa();
                    if(((testemsg) message).alg.equals("GA")){
                        TMessage.R.getorigem().PLista();
                    }
                    if(((testemsg) message).alg.equals("SA")){
                        TMessage.R.getorigem().SimAnnealing();
                    }
                    if(((testemsg) message).alg.equals("SGA")){
                        TMessage.R.getorigem().SimAnnealingGA();
                    }
                }
            }
            if (message instanceof MsgBusca) {
                MsgBusca BMessage = (MsgBusca) message;
                if (BMessage.R.getIdDestino() != BMessage.getIDDestino()) {
                    BMessage.add(this);
                    send(BMessage, Neighbors.get(new Random().nextInt(Neighbors.size())));
                } else {
                    BMessage.R.EliminaLoops();
                    BMessage.R.getorigem().Tab.addrota(BMessage.R);
                    if (BMessage.R.getorigem().Tab.getsize() >= PopulaçãoGA) {
                        final long initAlg = System.currentTimeMillis();
                        BMessage.R.getorigem().Controle(BMessage.getTempoInicio(), initAlg);
                    }
                }
            }
            if (message instanceof MsgBuscaSA) {
                MsgBuscaSA BMessage = (MsgBuscaSA) message;
                if (BMessage.R.getIdDestino() != BMessage.getIDDestino()) {
                    BMessage.add(this);
                    send(BMessage, Neighbors.get(new Random().nextInt(Neighbors.size())));
                } else {
                    BMessage.R.EliminaLoops();
                    BMessage.R.getorigem().Tab.addrota(BMessage.R);
                    BMessage.R.getorigem().ControleSA(BMessage.getTempoInicio());
                }
            }
            if (message instanceof MsgBuscaSG) {
                MsgBuscaSG BMessage = (MsgBuscaSG) message;
                if (BMessage.R.getIdDestino() != BMessage.getIDDestino()) {
                    BMessage.add(this);
                    send(BMessage, Neighbors.get(new Random().nextInt(Neighbors.size())));
                } else {
                    BMessage.R.EliminaLoops();
                    BMessage.R.getorigem().Tab.addrota(BMessage.R);
                    if (BMessage.R.getorigem().Tab.getsize() >= PopulaçãoSGA) {
                        final long initAlg = System.currentTimeMillis();
                        BMessage.R.getorigem().ControleSG(BMessage.getTempoInicio(), initAlg);
                    }
                }
            }
        }
    }

    @NodePopupMethod(menuText = "PLista")
    public void PLista() {
        //Destino=Integer.parseInt(JOptionPane.showInputDialog("Digite o destino"));
        timerP timer = new timerP();
        timer.startRelative(1, this);
    }
    
    @NodePopupMethod(menuText = "Sim. Annealing")
    public void SimAnnealing() {
        //Destino=Integer.parseInt(JOptionPane.showInputDialog("Digite o destino"));
        timerS timer = new timerS();
        timer.startRelative(1, this);
    }
    
    @NodePopupMethod(menuText = "Sim. Annealing GA")
    public void SimAnnealingGA() {
        //Destino=Integer.parseInt(JOptionPane.showInputDialog("Digite o destino"));
        timerSG timer = new timerSG();
        timer.startRelative(1, this);
    }

    public void PreencheTab() {
        final long T = System.currentTimeMillis();
        final SimpleNode Origem = this;
        for (int i = 0; i < PopulaçãoGA; i++) {
            send(new MsgBusca(Origem, Destino, T), Neighbors.get(new Random().nextInt(Neighbors.size())));
        }
    }
    
    public void PreencheTabSA() {
        final long T = System.currentTimeMillis();
        final SimpleNode Origem = this;
        send(new MsgBuscaSA(Origem, Destino, T), Neighbors.get(new Random().nextInt(Neighbors.size())));
    }
    
    public void PreencheTabSG() {
        final long T = System.currentTimeMillis();
        final SimpleNode Origem = this;
        for (int i = 0; i < PopulaçãoSGA; i++) {
            send(new MsgBuscaSG(Origem, Destino, T), Neighbors.get(new Random().nextInt(Neighbors.size())));
        }
    }

    public void Controle(long T, long initAlg) {
        if(contador<execucoes){
            Genetico G = new Genetico((TabelaRotas) Tab.getrota(PopulaçãoGA, Destino), Geracoes, 0.02, 0.9);
            M[contador]=G.Evoluir();
            testemsg NMessage = new testemsg(G.getrota(), T, "GA");
            send(NMessage, (SimpleNode) NMessage.R.getpos(1));
            contador++;
        }
        else{
            for(int i=0;i<Geracoes;i++){
                for(int j=0;j<execucoes;j++){
                    V[i]+=(M[j][i]);
                }
                V[i]=V[i]/30.0;
            }
            System.out.println("convm = [");
            for(int i = 0; i< Geracoes; i++){
                if(i!=Geracoes-1){
                    System.out.println(V[i]+", ");
                }
            }
            System.out.print("];  \n" +
            "%vetor com os pontos\n" +
            "plot(convm100, 'k-.');\n" +
            "xlabel('generation');\n" +
            "ylabel('fitness');\n" +
            "legend('GA - Cruz: 0.9 ; Mut: 0.05 ; Pop: "+PopulaçãoGA+" ; ')\n" +
            "title('Grafo de 100 nós')\n");
        }
    }
    
    public void ControleSA(long T) {
        if(contador<execucoes){
            SimulatedAnnealing SA = new SimulatedAnnealing((Rotas) Tab.getAnyRota(Destino), 1000.0, 100, 0.9, 4, 4);
            SA.Evoluir();
            testemsg NMessage = new testemsg(SA.getRota(), T, "SA");
            send(NMessage, (SimpleNode) NMessage.R.getpos(1));
            contador++;
        }
    }
    
    public void ControleSG(long T, long initAlg) {
        if(contador<execucoes){
            SAGenetico SAG = new SAGenetico((TabelaRotas) Tab.getrota(PopulaçãoSGA, Destino), Geracoes, 0.1, 0.8, 10);
            SAG.Evoluir();
            testemsg NMessage = new testemsg(SAG.getRota(), T, "SGA");
            send(NMessage, (SimpleNode) NMessage.R.getpos(1));
            contador++;
        }
    }


    public void InBuscaRand(int IDd) {
        int p, cont = 0;
        SimpleNode RAt;
        Rotas R = new Rotas();
        R.limpa();
        RAt = this;
        while (RAt.ID != IDd) {
            if (cont % 10 == 0) {
                EliminaLoops(R);
            }
            R.add(RAt);
            Random E = new Random();
            p = E.nextInt(RAt.Neighbors.size());
            RAt = RAt.Neighbors.get(p);
            cont++;
        }
        if (RAt.ID == IDd) {
            R.add(RAt);
            EliminaLoops(R);
            Tab.addrota(R);
        }
    }

    public Object EliminaLoops(Rotas R) {
        int b = 0;
        for (int n = 0; n < R.getsize(); n++) {
            for (int i = n + 1; i < R.getsize(); i++) {
                if (R.getpos(i).equals(R.getpos(n))) {
                    R.remlim(n, i);
                    b = 1;
                }
            }
        }
        if (b == 1) {
            EliminaLoops(R);
        }
        if (R.verifica()) {
            R.calccusto();
            return R;
        } else {
            return null;
        }
    }

    @Override
    public void preStep() {
    }

    @Override
    public void init() {
    }

    @Override
    public void neighborhoodChange() {
    }

    @Override
    public void postStep() {
        findNeighbors();
    }

    @Override
    public void checkRequirements() throws WrongConfigurationException {
    }
}
