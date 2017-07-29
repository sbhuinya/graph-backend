package com.fireeye.web;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
public class ContextData {

    private Set<Node> nodes = new HashSet<>();

    private Set<Edge> edges = new HashSet<>();

    public Set<Node> getNodes() {
        return nodes;
    }

    public void setNodes(Set<Node> nodes) {
        this.nodes = nodes;
    }

    public boolean addNode(Node node) {
        nodes.add(node);
        return true;
    }

    public Set<Edge> getEdges() {
        return edges;
    }

    public Boolean addEdge(Edge edge) {
        this.edges.add(edge);
        return true;
    }

    public void setEdges(Set<Edge> edges) {
        this.edges = edges;
    }
}
