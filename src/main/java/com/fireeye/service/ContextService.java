package com.fireeye.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fireeye.web.ContextData;
import com.fireeye.web.Edge;
import com.fireeye.web.Node;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
@Component
public class ContextService {



    private ESIndex esIndex;

    private static Map<String,String> indicatorTypeMapping;

    private static final String ALL = "all";

    static {
        indicatorTypeMapping = new HashMap<>();
        indicatorTypeMapping.put("ip", "ipv4-addr:value");
        indicatorTypeMapping.put("domain", "domain-name:value");
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
        GetResponse response = esIndex.getById("intel", "report", reportId);
        ContextData data = new ContextData();
        Set<String> nodesFetched = new HashSet<>();
        Set<String> relationshipsFetched = new HashSet<>();

        if(response.isExists()) {
            Map<String, Object> source =  response.getSource();
            List<String> references = (List<String>)source.get("object_refs");
            Node reportNode = new Node();
            reportNode.setId(response.getId());
            reportNode.setType(response.getType());
            reportNode.setLabel(response.getId());
            for(String ref: references) {
                if(!ref.startsWith("relationship--")) {
                    GetResponse refResponse = esIndex.getById("intel", null, ref);
                    String type = refResponse.getType();
                    if(!type.equals("relationship")) {
                        Node node = new Node();
                        node.setId(refResponse.getId());
                        node.setLabel(refResponse.getId());
                        node.setType(refResponse.getType());
                        node.setData(refResponse.getSource());
                        nodesFetched.add(refResponse.getId());
                        data.addNode(node);
                    }
                }

            }
            source.remove("object_refs");
            reportNode.setData(source);
            data.addNode(reportNode);
            fetchRelationsForEachNode(data.nodesAlreadyFetched(), data);
        }
        return data;
    }

    public ContextData getData(String searchString){

        ContextData result = new ContextData();
        SearchHits hits = esIndex.query(searchString);
//        Set<String> nodesFetched = new HashSet<>();
//        Set<String> relationshipsFetched = new HashSet<>();
        Node rootNode = new Node();
        rootNode.setId(searchString);
        rootNode.setLabel(searchString);
        rootNode.setType("search-term");
        HashMap<String, Object> rootData = new HashMap<>();
        rootData.put("search_string", searchString);
        rootNode.setData(rootData);

        createNodes(hits, result, rootNode);
        fetchRelationsForEachNode(result.nodesAlreadyFetched(), result);
        rootData.put("Total Nodes", result.getNodes().size());
        rootData.put("Total Edges", result.getEdges().size());
        result.addNode(rootNode);
        return result;
    }

    private void createNodes(SearchHits hits, ContextData data, Node rootNode) {
        Set<String> refNodes = new HashSet<>();

        for(SearchHit hit: hits) {
            Map<String, Object> sourceFields = hit.getSource();
            String documentType = (String) hit.getSourceAsMap().get("type");
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



    public static void main(String[] args) {
        ObjectMapper objectMapper = new ObjectMapper();

        ContextService service = new ContextService();
        ESSettings esSettings = new ESSettings();
        esSettings = esSettings.builder().clusterName("elasticsearch")
                .hostAndPort("localhost", 9300)
                .indexName("intel").build();
        ESIndex index = new ESIndex(esSettings);
        service.setEsIndex(index);
        ContextData data = service.getData("apt");
        try {
            System.out.println(objectMapper.writeValueAsString(data));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }
}
