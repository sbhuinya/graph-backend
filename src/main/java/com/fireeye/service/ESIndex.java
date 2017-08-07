package com.fireeye.service;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequestBuilder;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.engine.DocumentMissingException;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.QueryStringQueryBuilder;
import org.elasticsearch.script.Script;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.transport.client.PreBuiltTransportClient;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Created by LT-Mac-Akumar on 06/07/2017.
 */
public class ESIndex {

    /**
     * Thread safe ElasticSearch Java Client to perform Index operations
     */
    private static Client client;

    /**
     * The name of the index. Defaults to 'stix'
     */
    private final String indexName;

    /**
     * The parameter representing the cluster name key
     */
    static final String CLUSTER_NAME_PARAM = "cluster.name";

    /**
     * The parameter representing the number of shards key
     */
    static final String NUM_OF_SHARDS_PARAM = "number_of_shards";

    /**
     * The parameter representing the number of replicas key
     */
    static final String NUM_OF_REPLICAS_PARAM = "number_of_replicas";

    private final String DELETE_SCRIPT = "ctx._source.remove('<fieldToRemove>')";

    public ESIndex(ESSettings esSettings) {
        this.indexName = esSettings.getIndexName();

        try {
            if(client == null) {

//                LOGGER.debug("Initializing the Elastic Search Java Client with settings: " + esSettings);
                Settings settings = Settings.builder().put()
                        .put(CLUSTER_NAME_PARAM, esSettings.getClusterName()).build();
                List<InetSocketTransportAddress> addresses = new ArrayList<>();
                for(String host: esSettings.getHostToPortMapping().keySet()) {
                    InetSocketTransportAddress addr = new InetSocketTransportAddress(InetAddress.getByName(host), esSettings.getHostToPortMapping().get(host));
                    addresses.add(addr);
                }

                InetSocketTransportAddress socketAddresses[] = new InetSocketTransportAddress[addresses.size()];
                TransportClient tc = new PreBuiltTransportClient(settings);
                tc.addTransportAddresses(addresses.toArray(socketAddresses));
                client = tc;
//                LOGGER.debug("Successfully initialized the client");
            }

            IndicesExistsResponse exists = client.admin().indices().exists(new IndicesExistsRequest(indexName)).get();
            if(!exists.isExists()) {
                Settings indexSettings = Settings.builder()
                        .put(NUM_OF_SHARDS_PARAM, esSettings.getShards())
                        .put(NUM_OF_REPLICAS_PARAM, esSettings.getReplicas())
                        .build();
//                LOGGER.debug("Index with name " + indexName + " does not exist yet. Creating one with settings: " + indexSettings.toString());
                client.admin().indices().prepareCreate(indexName).setSettings(indexSettings).get();
            }
            exists = client.admin().indices().exists(new IndicesExistsRequest("nvd")).get();
            if(!exists.isExists()) {
                Settings indexSettings = Settings.builder()
                        .put(NUM_OF_SHARDS_PARAM, esSettings.getShards())
                        .put(NUM_OF_REPLICAS_PARAM, esSettings.getReplicas())
                        .build();
//                LOGGER.debug("Index with name " + indexName + " does not exist yet. Creating one with settings: " + indexSettings.toString());
                client.admin().indices().prepareCreate("nvd").setSettings(indexSettings).get();
            }
        }catch (Exception e) {
            throw new RuntimeException("Exception occurred while instantiating ElasticSearch Text Index", e);
        }

    }

    public GetResponse getById(String indexName, String documentType, String id) {
        return client.prepareGet(indexName, documentType, id).get();

    }

    public String removeProperty(String index, String documentType, String id, String fieldToRemove) {
        String result = null;
        String deleteScript = DELETE_SCRIPT.replaceAll("<fieldToRemove>", fieldToRemove);

        UpdateRequest updateRequest = new UpdateRequest(index, documentType, id)
                .script(new Script(deleteScript));

        try {
            UpdateResponse response = client.update(updateRequest).get();
            result = response.getId();
        }catch(Exception e) {
            if( ExceptionUtils.getRootCause(e) instanceof DocumentMissingException) {
                e.printStackTrace();
//                LOGGER.debug("Trying to delete values from a missing document. Ignoring deletion of entity: ", entity);
            } else {
                throw new RuntimeException("Unable to delete entity.", e);
            }
        }
        return result;
    }

    public SearchHits queryByFields(String qs, String field) {
        SearchResponse response = client.prepareSearch("nvd", indexName)
                .setQuery(QueryBuilders.queryStringQuery(qs).field(field))
                .setFetchSource(true)
                .setFrom(0).setSize(100)
                .get();
        return response.getHits();
    }
    public SearchHits query(String qs) {
        SearchResponse response = client.prepareSearch("nvd", indexName)
                .setQuery(QueryBuilders.queryStringQuery(qs))
                .setFetchSource(true)
                .setFrom(0).setSize(1000)
                .get();
        return response.getHits();
    }

    public SearchHits queryForIndicators(String qs, String documentType, String... fieldsToReturn) {
        QueryStringQueryBuilder queryBuilder = new QueryStringQueryBuilder(quote(qs)).field("pattern");

        SearchResponse response = client.prepareSearch(indexName).setTypes(documentType)
                .setQuery(queryBuilder)
                .setFetchSource(fieldsToReturn, null)
                .setFrom(0).setSize(1000)
                .get();
        return response.getHits();
    }

    public static String quote(String s) {
        return new StringBuilder()
                .append('\"')
                .append(s)
                .append('\"')
                .toString();
    }

    public SearchHits termQuery(String field, Set<String> valuesToSearch, String[] indexNames, String[] fieldsToReturn, String... documentTypes) {
        QueryBuilder qb = QueryBuilders.termsQuery(field, valuesToSearch);
        SearchRequestBuilder srb = client.prepareSearch(indexNames)
                .setQuery(qb)
                .setFrom(0).setSize(1000);
        if(documentTypes.length> 0) {
            srb.setTypes(documentTypes);
        }
        if(fieldsToReturn != null && fieldsToReturn.length > 0) {
            srb.setFetchSource(fieldsToReturn, null);
        }else {
            srb.setFetchSource(true);
        }

        SearchResponse response = srb.get();
        return response.getHits();
//        client.termQue
    }

    public String upsertDocument(String index, String type, String id, byte[] jsonObject) throws Exception{

        IndexRequest indexRequest = new IndexRequest(index, type, id).source(jsonObject, XContentType.JSON);
        UpdateRequest updateRequest = new UpdateRequest(index, type, id).doc(jsonObject, XContentType.JSON).upsert(indexRequest);

        UpdateResponse response = client.update(updateRequest).get();
        //TODO: Do some Status checking before returning id
        return response.getId();
    }

    public GetResponse getById(String type, String id) {
        return client.prepareGet("*", type, id).get();

    }

    public String deleteDocument(String index, String documentType, String id) {
        DeleteResponse deleteResponse = client.prepareDelete(index, documentType, id).get();
        return deleteResponse.status().name();
    }

    public Boolean documentExists(String type, String id) {
        if(getById(type, id).isExists() == false){
            SearchHits hits = query("id:".concat(id));
            if(hits.getHits().length > 0) {
                return true;
            } else {
                return false;
            }
        }else {
            return true;
        }
    }




}
