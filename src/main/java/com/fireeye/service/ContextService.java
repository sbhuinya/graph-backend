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

    public static final String TOTAL_NODES = "Total Nodes";
    public static final String TOTAL_EDGES = "Total Edges";
    public static final String DOCUMENT_TYPE = "type";
    public static final String DEFINITION_TYPE = "definition_type";
    public static final String DEFINITION = "definition";
    public static final String TLP = "tlp";
    public static final String DASH = "-";
    public static final String ID = "id";
    public static final String LABEL = "label";
    public static final String REF = "ref";
    public static final String REF_DASH = "ref--";
    public static final String RELATIONSHIP_DASH = "relationship--";
    public static final String FOUND_IN = "FOUND_IN";
    public static final String SOURCE_REF = "source_ref";
    public static final String TARGET_REF = "target_ref";
    public static final String RELATIONSHIP_TYPE = "relationship_type";
    public static final String NVD_INDEX = "nvd";
    public static final String KEY_NAME = "key_name";
    public static final String KEY_VALUE = "key_value";
    public static final String ACTION = "action";
    public static final String DELETE_ACTION = "delete";
    public static final String MODIFIED = "modified";
    public static final String REFS = "refs";
    private ObjectMapper objectMapper = new ObjectMapper();

    private ESIndex esIndex;

    private static Map<String,String> indicatorTypeMapping;

    private static Map<String, String> documentTypeToIndexMapping;

    public static final String IP = "ip";

    public static final String IPV4_ADDR_VALUE = "ipv4-addr:value";

    public static final String DOMAIN = "domain";

    public static final String DOMAIN_NAME_VALUE = "domain-name:value";

    public static final String MARKING_DEFINITION = "marking-definition";

    public static final String RELATIONSHIP = "relationship";

    public static final String INTEL_INDEX = "intel";

    //TODO: Move to Central Config
    static {
        documentTypeToIndexMapping = new HashMap<>();
        documentTypeToIndexMapping.put(RELATIONSHIP, RELATIONSHIP);
        documentTypeToIndexMapping.put("cpe", "nvd");
        documentTypeToIndexMapping.put("cve", "nvd");
        documentTypeToIndexMapping.put("course-of-action", INTEL_INDEX);
        documentTypeToIndexMapping.put("indicator", INTEL_INDEX);
        documentTypeToIndexMapping.put("malware", INTEL_INDEX);
        documentTypeToIndexMapping.put("identity", INTEL_INDEX);
        documentTypeToIndexMapping.put(MARKING_DEFINITION, INTEL_INDEX);
        documentTypeToIndexMapping.put("campaign", INTEL_INDEX);
        documentTypeToIndexMapping.put("statement", INTEL_INDEX);
//        documentTypeToIndexMapping.put("threat-actor", INTEL_INDEX);
    }

    //TODO: Move to central Config
    static {
        indicatorTypeMapping = new HashMap<>();
        indicatorTypeMapping.put(IP, IPV4_ADDR_VALUE);
        indicatorTypeMapping.put(DOMAIN, DOMAIN_NAME_VALUE);
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
        SearchHits hits = esIndex.queryByFields(reportId, ID);
        Node rootNode = createRootNode(reportId);
        ContextData result =  prepareData(hits, rootNode);
        rootNode.getData().put(TOTAL_NODES, result.getNodes().size());
        rootNode.getData().put(TOTAL_EDGES, result.getEdges().size());
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
        SearchHits hits = esIndex.query(searchString);
        Node rootNode = createRootNode(searchString);
        ContextData result =  prepareData(hits, rootNode);
        rootNode.getData().put(TOTAL_NODES, result.getNodes().size());
        rootNode.getData().put(TOTAL_EDGES, result.getEdges().size());
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
            String documentType = (String) hit.getSourceAsMap().get(DOCUMENT_TYPE);
            documentType = documentType != null ? documentType : hit.getType();
            if(documentType.equals(MARKING_DEFINITION)) {
                documentType = (String) hit.getSourceAsMap().get(DEFINITION_TYPE);
                String tlp = (String)((HashMap)hit.getSource().get(DEFINITION)).get(TLP);
                if(tlp != null) {
                    documentType = documentType.concat(DASH).concat(tlp);
                }
            }
            String id = (String) hit.getSourceAsMap().get(ID);
            if(!data.isNodePresent(id)) {
                String label =  hit.getSourceAsMap().get(LABEL) != null?  (String) hit.getSourceAsMap().get(LABEL): id;
                Node node = new Node();
                node.setId(id);
                node.setData(sourceFields);
                node.setType(documentType);
                node.setLabel(label);
                data.addNode(node);
                if(rootNode != null) {
                    data.addEdge(createRootRelationship(rootNode, node));
                }
                for(String key: sourceFields.keySet()) {
                    if(key.endsWith(REF)) {
                        String keyId = (String)sourceFields.get(key);
                        if(!data.isNodePresent(keyId)) {
                            //Create a relationship edge first
                            Edge edge = new Edge();
                            edge.setId(REF_DASH.concat(UUID.randomUUID().toString()));
                            edge.setSource(id);
                            edge.setTarget(keyId);
                            edge.setInternalType(key.substring(0, key.indexOf("_ref")));
                            data.addEdge(edge);
                            refNodes.add((String)sourceFields.get(key));
                        }

                    } else if(key.endsWith(REFS)) {
                        List<String> references = (List)sourceFields.get(key);
                        for(String ref: references) {
                            if(!data.isNodePresent(ref)) {
                                Edge edge = new Edge();
                                edge.setId(REF_DASH.concat(UUID.randomUUID().toString()));
                                edge.setSource(id);
                                edge.setTarget(ref);
                                edge.setInternalType(key.substring(0, key.indexOf("_refs")));
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
        edge.setId(RELATIONSHIP_DASH.concat(UUID.randomUUID().toString()));
        edge.setSource(sourceNode.getId());
        edge.setTarget(targetNode.getId());
        edge.setInternalType(FOUND_IN);
        return edge;
    }

    private void fetchRelationsForEachNode(Set<String> nodesFetched, ContextData data) {
        String[] indexesToSearch = new String[1];
        indexesToSearch[0] = RELATIONSHIP;
        SearchHits sourceRelationships = esIndex.termQuery(SOURCE_REF, nodesFetched, indexesToSearch, null, RELATIONSHIP);
        SearchHits targetRelationships = esIndex.termQuery(TARGET_REF, nodesFetched, indexesToSearch, null, RELATIONSHIP);
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
            String rtype = (String)rsource.get(RELATIONSHIP_TYPE);
            String sourceNode = (String)rsource.get(SOURCE_REF);
            String targetNode = (String)rsource.get(TARGET_REF);
            String rid = (String)rsource.get(ID);
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
        indexNames[0] = INTEL_INDEX;
        indexNames[1] = NVD_INDEX;
        return esIndex.termQuery(ID, nodesToFetch, indexNames, null);
    }



    enum RelationshipFetchedFor {
        SOURCE,
        TARGET
    }


    public String updateDocument(String jsonData) throws Exception{

        String idUpdated = null;
        Map values = objectMapper.readValue(jsonData, Map.class);
        if((values.containsKey(ID))) {
            String id = (String)values.get(ID);
            String documentType = (String)values.get(DOCUMENT_TYPE);
            String keyName = (String)values.get(KEY_NAME);
            String keyValue = (String)values.get(KEY_VALUE);
            String action = (String)values.get(ACTION);
            if(DELETE_ACTION.equals(action)) {
                esIndex.removeProperty(documentTypeToIndexMapping.get(documentType), documentType, id, keyName);
            } else {
                String jsonToUpdate = jsonBuilder()
                        .startObject()
                        .field(keyName, keyValue)
                        .field(MODIFIED, LocalDateTime.now(Clock.systemUTC()))
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
