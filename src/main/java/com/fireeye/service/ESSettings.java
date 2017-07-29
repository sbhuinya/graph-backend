package com.fireeye.service;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by LT-Mac-Akumar on 06/07/2017.
 */
public class ESSettings {

    /**
     * Map of hosts and ports. The host could also be an IP Address
     */
    private Map<String,Integer> hostToPortMapping;

    /**
     * Name of the Cluster. Defaults to 'elasticsearch'
     */
    private String clusterName;

    /**
     * Number of shards. Defaults to '1'
     */
    private Integer shards;

    /**
     * Number of replicas. Defaults to '1'
     */
    private Integer replicas;

    /**
     * Name of the index. Defaults to 'jena-text'
     */
    private String indexName;


    public Map<String, Integer> getHostToPortMapping() {
        return hostToPortMapping;
    }

    public void setHostToPortMapping(HashMap<String, Integer> hostToPortMapping) {
        this.hostToPortMapping = hostToPortMapping;
    }

    public ESSettings.Builder builder() {
        return new ESSettings.Builder();
    }

    /**
     * Convenient builder class for building ESSettings
     */
    public static class Builder {

        ESSettings settings;

        public Builder() {
            this.settings = new ESSettings();
            this.settings.setClusterName("elasticsearch");
            this.settings.setShards(1);
            this.settings.setReplicas(1);
            this.settings.setHostToPortMapping(new HashMap<String, Integer>());
            this.settings.setIndexName("intel");
        }


        public Builder indexName(String indexName) {
            if(indexName != null && !indexName.isEmpty()) {
                this.settings.setIndexName(indexName);
            }
            return this;
        }

        public Builder clusterName(String clusterName) {
            if(clusterName != null && !clusterName.isEmpty()) {
                this.settings.setClusterName(clusterName);
            }
            return this;

        }

        public Builder shards(Integer shards) {
            if (shards != null) {
                this.settings.setShards(shards);
            }
            return this;
        }

        public Builder replicas(Integer replicas) {
            if(replicas != null) {
                this.settings.setReplicas(replicas);
            }
            return this;
        }

        public Builder hostAndPort(String host, Integer port) {
            if(host != null && port != null) {
                this.settings.getHostToPortMapping().put(host, port);
            }
            return this;

        }

        public Builder hostAndPortMap(Map<String, Integer> hostAndPortMap) {
            if(hostAndPortMap != null) {
                this.settings.getHostToPortMapping().putAll(hostAndPortMap);
            }

            return this;
        }

        public ESSettings build() {
            return this.settings;
        }

    }

    public String getClusterName() {
        return clusterName;
    }

    public void setClusterName(String clusterName) {
        this.clusterName = clusterName;
    }

    public Integer getShards() {
        return shards;
    }

    public void setShards(Integer shards) {
        this.shards = shards;
    }

    public Integer getReplicas() {
        return replicas;
    }

    public void setReplicas(Integer replicas) {
        this.replicas = replicas;
    }

    public String getIndexName() {
        return indexName;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }
}
