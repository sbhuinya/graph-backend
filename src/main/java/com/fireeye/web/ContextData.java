package com.fireeye.web;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
public class ContextData {

    private Set<Node> nodes = new HashSet<>();

    private Set<Edge> edges = new HashSet<>();

    private Set<String> nodesAdded = new HashSet<>();

    private Set<String> edgesAdded = new HashSet<>();

    public Set<Node> getNodes() {
        return nodes;
    }

    public void addNode(Node node) {
        if(! nodesAdded.contains(node.getId())) {
            nodes.add(node);
            nodesAdded.add(node.getId());
        }
    }

    public Set<Edge> getEdges() {
        return edges;
    }

    public void addEdge(Edge edge) {
        if(!edgesAdded.contains(edge.getId())) {
            this.edges.add(edge);
            edgesAdded.add(edge.getId());
        }

    }

    public Set<String> nodesAlreadyFetched() {
        return nodesAdded;
    }

    public Set<String> edgesAlreadyFetched() {
        return edgesAdded;
    }

    public Boolean isNodePresent(String nodeId) {
        return nodesAdded.contains(nodeId);
    }

    public Boolean isEdgePresent(String edgeId) {
        return edgesAdded.contains(edgeId);
    }

}
