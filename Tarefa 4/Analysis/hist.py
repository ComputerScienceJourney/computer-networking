import matplotlib.pyplot as plt
import seaborn as sns
import scipy
from math import sqrt
from numpy import mean
from scipy.stats import sem
from scipy.stats import t
from scipy.stats import kruskal
from scipy.stats import wilcoxon

# function for calculating the t-test for two independent samples
def independent_ttest(data1, data2, alpha):
    # calculate means
    mean1, mean2 = mean(data1), mean(data2)
    # calculate standard errors
    se1, se2 = sem(data1), sem(data2)
    # standard error on the difference between the samples
    sed = sqrt(se1**2.0 + se2**2.0)
    # calculate the t statistic
    t_stat = (mean1 - mean2) / sed
    # degrees of freedom
    df = len(data1) + len(data2) - 2
    # calculate the critical value
    cv = t.ppf(1.0 - alpha, df)
    # calculate the p-value
    p = (1.0 - t.cdf(abs(t_stat), df)) * 2.0
    # return everything
    return t_stat, df, cv, p

def main():
    files = ["tppaee/SAvsGR1.txt", "tppaee/SAvsGR2.txt", "tppaee/SAvsGR3.txt"]
    c = 1
    for filename in files:
        file = open(filename)
        i = 0
        sa = []
        gr = []
        for line in file:
            if i >= 1:
                [a, b] = line.split(";")
                sa.append(int(a))
                gr.append(int(b))
            i += 1
        print("Cenario "+str(c))
        c += 1
        alpha = 0.05
        print(wilcoxon(sa, gr))

        #t_stat, df, cv, p = independent_ttest(sa, gr, alpha)
        # interpret via critical value
        #if abs(t_stat) <= cv:
        #    print('Accept null hypothesis that the means are equal.')
        #else:
        #    print('Reject the null hypothesis that the means are equal.')
        #print(p)
        # interpret via p-value
        #if p > alpha:
            #print('Accept null hypothesis that the means are equal.')
        #else:
            #print('Reject the null hypothesis that the means are equal.')


#print(scipy.stats.shapiro(sa))
#print(scipy.stats.shapiro(gr))

#fig = plt.figure(figsize=(15,5))
#ax = fig.add_subplot(111)

#sns.distplot(sa, kde=True, ax=ax, hist=False, bins=10)
#sns.distplot(gr, kde=True, ax=ax, hist=False, bins=10)

#plt.legend(labels=['SA', 'GRASP'])
#plt.show()


if __name__ == '__main__':
    main()