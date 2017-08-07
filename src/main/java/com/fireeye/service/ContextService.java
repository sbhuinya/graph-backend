package com.fireeye.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fireeye.web.ContextData;
import com.fireeye.web.Edge;
import com.fireeye.web.Node;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.*;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
@Component
public class ContextService {

    private ObjectMapper objectMapper = new ObjectMapper();

    private ESIndex esIndex;

    private static Map<String,String> indicatorTypeMapping;

    private static Map<String, String> documentTypeToIndexMapping;

    private static final String ALL = "all";

    //TODO: Move to central Config
    static {
        indicatorTypeMapping = new HashMap<>();
        indicatorTypeMapping.put("ip", "ipv4-addr:value");
        indicatorTypeMapping.put("domain", "domain-name:value");
    }

    //TODO: Move to Central Config
    static {
        documentTypeToIndexMapping = new HashMap<>();
        documentTypeToIndexMapping.put("relationship", "relationship");
        documentTypeToIndexMapping.put("cpe", "nvd");
        documentTypeToIndexMapping.put("cve", "nvd");
        documentTypeToIndexMapping.put("course-of-action", "intel");
        documentTypeToIndexMapping.put("indicator", "intel");
        documentTypeToIndexMapping.put("malware", "intel");
        documentTypeToIndexMapping.put("identity", "intel");
        documentTypeToIndexMapping.put("marking-definition", "intel");
        documentTypeToIndexMapping.put("campaign", "intel");
        documentTypeToIndexMapping.put("statement", "intel");
    }

    public void setEsIndex(ESIndex esIndex) {
        this.esIndex = esIndex;
    }


    public Map<Integer,Map<String, Object>> getIndicators(String type) {
        SearchHits hits = esIndex.queryForIndicators(indicatorTypeMapping.get(type), "indicator", "pattern", "description");
        Map<Integer,Map<String, Object>> result = new HashMap<>();
        Map<String, Object> totalCount = new HashMap<>();
        Integer count = 0;
        totalCount.put("total-count", String.valueOf(hits.getTotalHits()));
        result.put(count, totalCount);

        for(SearchHit hit: hits) {
            count = count + 1;
            result.put(count, hit.getSource());

        }
        return result;
    }

    public ContextData getReportData(String reportId) {

        SearchHits hits = esIndex.queryByFields(reportId, "id");
        Node rootNode = createRootNode(reportId);
        ContextData result =  prepareData(hits, rootNode);
        rootNode.getData().put("Total Nodes", result.getNodes().size());
        rootNode.getData().put("Total Edges", result.getEdges().size());
        result.addNode(rootNode);
        return result;
    }

    private Node createRootNode(String searchString) {
        Node rootNode = new Node();
        rootNode.setId(searchString);
        rootNode.setLabel(searchString);
        rootNode.setType("search-term");
        HashMap<String, Object> rootData = new HashMap<>();
        rootData.put("search_string", searchString);
        rootNode.setData(rootData);
        return rootNode;
    }


    public ContextData getData(String searchString) {
//        ContextData result = new ContextData();
        SearchHits hits = esIndex.query(searchString);
        Node rootNode = createRootNode(searchString);
        ContextData result =  prepareData(hits, rootNode);
        rootNode.getData().put("Total Nodes", result.getNodes().size());
        rootNode.getData().put("Total Edges", result.getEdges().size());
        result.addNode(rootNode);
        return result;

    }

    public ContextData prepareData(SearchHits hits, Node rootNode){

        ContextData result = new ContextData();


        createNodes(hits, result, rootNode);
        fetchRelationsForEachNode(result.nodesAlreadyFetched(), result);

        return result;
    }

    private void createNodes(SearchHits hits, ContextData data, Node rootNode) {
        Set<String> refNodes = new HashSet<>();

        for(SearchHit hit: hits) {
            Map<String, Object> sourceFields = hit.getSource();
            String documentType = (String) hit.getSourceAsMap().get("type");
            documentType = documentType != null ? documentType : hit.getType();
            if(documentType.equals("marking-definition")) {
                documentType = (String) hit.getSourceAsMap().get("definition_type");
                String tlp = (String)((HashMap)hit.getSource().get("definition")).get("tlp");
                if(tlp != null) {
                    documentType = documentType.concat("-").concat(tlp);
                }

            }
            String id = (String) hit.getSourceAsMap().get("id");
            if(!data.isNodePresent(id)) {
                //TODO: Change it to take label from label field if present
                String label =  hit.getSourceAsMap().get("label") != null?  (String) hit.getSourceAsMap().get("label"): id;
                Node node = new Node();
                node.setId(id);
                node.setData(sourceFields);
                node.setType(documentType);
                node.setLabel(label);
//                nodesFetched.add(id);
                data.addNode(node);
                if(rootNode != null) {
                    data.addEdge(createRootRelationship(rootNode, node));
                }
                for(String key: sourceFields.keySet()) {
                    if(key.endsWith("ref")) {
                        String keyId = (String)sourceFields.get(key);
                        if(!data.isNodePresent(keyId)) {
                            //Create a relationship edge first
                            Edge edge = new Edge();
                            edge.setId("ref--".concat(UUID.randomUUID().toString()));
                            edge.setSource(id);
                            edge.setTarget(keyId);
                            edge.setInternalType("Reference");
                            data.addEdge(edge);
                            refNodes.add((String)sourceFields.get(key));
                        }

                    } else if(key.endsWith("refs")) {
                        List<String> references = (List)sourceFields.get(key);
                        for(String ref: references) {
                            if(!data.isNodePresent(ref)) {
                                Edge edge = new Edge();
                                edge.setId("ref--".concat(UUID.randomUUID().toString()));
                                edge.setSource(id);
                                edge.setTarget(ref);
                                edge.setInternalType("Reference");
                                data.addEdge(edge);
                                refNodes.add(ref);
                            }
                        }
                    }
                }
                if(!refNodes.isEmpty()) {
                    SearchHits newHits = fetchNodesById(refNodes);
                    createNodes(newHits, data, null);
                }

            }


        }

    }

    private Edge createRootRelationship(Node sourceNode, Node targetNode) {
        Edge edge = new Edge();
        edge.setId("relationship--".concat(UUID.randomUUID().toString()));
        edge.setSource(sourceNode.getId());
        edge.setTarget(targetNode.getId());
        edge.setInternalType("FOUND_IN");
        return edge;
    }

    private void fetchRelationsForEachNode(Set<String> nodesFetched, ContextData data) {
        String[] indexesToSearch = new String[1];
        indexesToSearch[0] = "relationship";
        SearchHits sourceRelationships = esIndex.termQuery("source_ref", nodesFetched, indexesToSearch, null, "relationship");
        SearchHits targetRelationships = esIndex.termQuery("target_ref", nodesFetched, indexesToSearch, null, "relationship");
        Set<String> nodesToFetch = new HashSet<>();
//        allFetchedNodes.addAll(nodesFetched);
        createEdges(sourceRelationships, data, RelationshipFetchedFor.SOURCE, nodesToFetch);
        createEdges(targetRelationships, data, RelationshipFetchedFor.TARGET, nodesToFetch);
        if(!nodesToFetch.isEmpty()) {
            SearchHits hits = fetchNodesById(nodesToFetch);
            if(hits.getTotalHits() > 0) {
                createNodes(hits, data, null);

            }

            fetchRelationsForEachNode(nodesToFetch, data);
        }

    }

    private void createEdges(SearchHits relationships, ContextData data, RelationshipFetchedFor fetchedFor, Set<String> nodesToFetch) {
        for(SearchHit relationship: relationships) {
            Map rsource = relationship.getSource();
            String rtype = (String)rsource.get("relationship_type");
            String sourceNode = (String)rsource.get("source_ref");
            String targetNode = (String)rsource.get("target_ref");
            String rid = (String)rsource.get("id");
            if(!data.isEdgePresent(rid)) {
                Edge edge = new Edge();
                edge.setId(rid);
                edge.setSource(sourceNode);
                edge.setTarget(targetNode);
                edge.setInternalType(rtype);
                edge.setData(relationship.getSource());
                data.addEdge(edge);
//                relationshipsFetched.add(rid);
            }


            if(fetchedFor.equals(RelationshipFetchedFor.SOURCE)) {
                //Get the list of Target Nodes that havent yet been fetched
                if(!data.isNodePresent(targetNode)){
                    nodesToFetch.add(targetNode);
                }
            }else {
                if(!data.isNodePresent(sourceNode)) {
                    nodesToFetch.add(sourceNode);
                }
            }
        }
    }

    private SearchHits fetchNodesById(Set<String> nodesToFetch) {
        String[] indexNames = new String[2];
        indexNames[0] = "intel";
        indexNames[1] = "nvd";
        return esIndex.termQuery("id", nodesToFetch, indexNames, null);
    }



    enum RelationshipFetchedFor {
        SOURCE,
        TARGET
    }


    public String updateDocument(String jsonData) throws Exception{

        String idUpdated = null;
        Map values = objectMapper.readValue(jsonData, Map.class);
        if((values.containsKey("id"))) {
            String id = (String)values.get("id");
            String documentType = (String)values.get("type");
            String keyName = (String)values.get("key_name");
            String keyValue = (String)values.get("key_value");
            String action = (String)values.get("action");
            if("delete".equals(action)) {
                esIndex.removeProperty(documentTypeToIndexMapping.get(documentType), documentType, id, keyName);
            } else {
                String jsonToUpdate = jsonBuilder()
                        .startObject()
                        .field(keyName, keyValue)
                        .field("modified", LocalDateTime.now(Clock.systemUTC()))
                        .endObject().string();
                idUpdated = esIndex.upsertDocument(documentTypeToIndexMapping.get(documentType), documentType, id, jsonToUpdate.getBytes());
            }

        }

        return idUpdated;
    }

    public String deleteDocument(String documentId, String documentType) {
        return esIndex.deleteDocument(documentTypeToIndexMapping.get(documentType), documentType, documentId);
    }

}
