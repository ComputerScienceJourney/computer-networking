import pandas as pd
import statsmodels.api as sm
from statsmodels.formula.api import ols
import scipy.stats as stats
import matplotlib.pyplot as plt
import seaborn as sns


def main():
    net = 'random144'
    t = ['SAvsGA', 'SAvsGAalg', 'SGAvsGA', 'SGAvsGAalg']
    v = 3
    if v < 2:
        alg1 = 'SA'
        alg2 = 'GA'
    else:
        alg1 = 'SGA'
        alg2 = 'GA'
    df = pd.read_csv("test2106/"+net+"/"+ t[v]+".txt", sep=";")
    df_melt = pd.melt(df.reset_index(), id_vars=['index'], value_vars=[alg1, alg2])
    df_melt.columns = ['index', 'treatments', 'value']
    ax = sns.boxplot(x='treatments', y='value', data=df_melt, color='#99c2a2')
    ax = sns.swarmplot(x="treatments", y="value", data=df_melt, color='#7d0013')

    fvalue, pvalue = stats.f_oneway(df[alg1], df[alg2])
    print(fvalue, pvalue)
    model = ols('value ~ C(treatments)', data=df_melt).fit()
    anova_table = sm.stats.anova_lm(model, typ=2)
    print(anova_table);
    #plt.title(net + " " + t[v])
    plt.show()


if __name__ == '__main__':
    main()
