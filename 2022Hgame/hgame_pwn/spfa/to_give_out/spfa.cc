// g++ spfa.cc -o spfa
#include <stdio.h>
#include <stdlib.h>
#include <queue>
#include <string.h>

#define NODES 210
#define EDGES 610

struct EDGE
{
    long long nxt, to, dis;
} edge[EDGES];

long long n, m, w, a, b, num_edge, t;
long long head[NODES], vis[NODES], dist[NODES], cnt[NODES];

void _add(long long from, long long to, long long dis)
{
    edge[++num_edge].to = to;
    edge[num_edge].dis = dis;
    edge[num_edge].nxt = head[from];
    head[from] = num_edge;
}

void spfa(long long s)
{
    std::queue<int> q;
    q.push(s);
    dist[s] = 0;
    vis[s] = 1;
    while (!q.empty())
    {
        long long u = q.front();
        q.pop();
        vis[u] = 0;
        for (long long i = head[u]; i; i = edge[i].nxt)
        {
            long long v = edge[i].to;
            if (dist[v] > dist[u] + edge[i].dis)
            {
                dist[v] = dist[u] + edge[i].dis;
                if (vis[v] == 0)
                {
                    vis[v] = 1;
                    q.push(v);
                }
            }
        }
    }
}

void backd00r()
{
    system("/bin/sh");
}

void init_io()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    long long t;

    init_io();

    printf("how many datas?\n>> ");
    scanf("%lld", &t);
    while (t--)
    {
        memset(vis, 0, sizeof(vis));
        memset(dist, 0, sizeof(dist));
        memset(cnt, 0, sizeof(cnt));
        memset(head, 0, sizeof(head));
        memset(dist, 127 / 3, sizeof(dist));
        printf("how many nodes?\n>> ");
        scanf("%lld", &n);
        printf("how many edges?\n>> ");
        scanf("%lld", &m);
        printf("input edges in the\n[from] [to] [distant]\nformat\n");
        for (long long i = 0; i < m; i++)
        {
            scanf("%lld%lld%lld", &a, &b, &w);
            _add(a, b, w);
        }

        printf("you want to start from which node?\n>> ");
        long long x;
        scanf("%lld", &x);

        spfa(x);

        printf("calc done!\nwhich path you are interested %lld to ?\n>> ", x);
        scanf("%lld", &x);
        printf("the length of the shortest path is %lld\n", dist[x]);
    }
    return 0;
}
