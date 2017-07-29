package com.fireeye.web;

import java.util.Map;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
public class Edge {

    private String id;

    private String internalType;

    private String source;

    private String target;

    private Map<String, Object> data;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getInternalType() {
        return internalType;
    }

    public void setInternalType(String internalType) {
        this.internalType = internalType;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Edge edge = (Edge) o;

        if (!internalType.equals(edge.internalType)) return false;
        if (!source.equals(edge.source)) return false;
        return target.equals(edge.target);

    }

    @Override
    public int hashCode() {
        int result = internalType.hashCode();
        result = 31 * result + source.hashCode();
        result = 31 * result + target.hashCode();
        return result;
    }
}
