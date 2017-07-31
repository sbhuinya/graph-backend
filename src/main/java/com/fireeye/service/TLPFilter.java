package com.fireeye.service;

import com.fireeye.web.ContextData;
import com.fireeye.web.Edge;
import com.fireeye.web.Node;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;

import java.util.*;

/**
 * Created by LT-Mac-Akumar on 13/07/2017.
 */
//@Component
public class TLPFilter implements Filter<ContextData, String> {

//    @Autowired
    private ESIndex esIndex;

    public ESIndex getEsIndex() {
        return esIndex;
    }

    public void setEsIndex(ESIndex esIndex) {
        this.esIndex = esIndex;
    }

    @Override
    public void filter(ContextData contextData, String filterCriteria) {
        Set<Node> nodes = contextData.getNodes();

        List<Node> nodesToRemove = new ArrayList<>();
        List<String> nodeIdsToRemove = new ArrayList<>();

        try {

            for(Node node: nodes) {

                Map<String, List> fieldToNewValuesMap = new HashMap<>();
                Map<String, Object> data = node.getData();
                if(node.getData() == null) {
                    continue;
                }
                List<String> markingIds = (List<String>)data.get("object_marking_refs");
                if(markingIds != null && !markingIds.isEmpty()) {
                    List<String> fieldsToReturn = new ArrayList<>();
//                    fieldsToReturn.add("definition.tlp");
                    Set<String> markingIdSet = new HashSet<>(markingIds);
                    try {
                        String[] indexNames = new String[1];
                        indexNames[0] = "intel";
                        SearchHits hits = esIndex.termQuery("id", markingIdSet, indexNames, fieldsToReturn.toArray(new String[0]), "marking-definition");
                        for(SearchHit hit: hits) {
                            if(hit.getSource() != null && ((HashMap)hit.getSource()).get("definition") != null && ((HashMap)hit.getSource().get("definition")).get("tlp") != null) {
                                String tlp = (String)((HashMap)hit.getSource().get("definition")).get("tlp");
                                if(value(tlp) > value(filterCriteria)) {
                                    //Remove the node
                                    nodesToRemove.add(node);
                                    nodeIdsToRemove.add(node.getId());
                                    continue;
//                                contextData.getNodes().remove(node);
                                } else {
                                    String markingDefId = (String) hit.getSource().get("id");
                                    String definitionType = (String) hit.getSource().get("definition_type");
                                    //Add a marking definition node and an edge from the node to the marking definition
                                    if(!contextData.isNodePresent(markingDefId)) {
                                        Node markingDefNode = new Node();
                                        markingDefNode.setId(markingDefId);
                                        markingDefNode.setType(tlp != null ? tlp : definitionType);
                                        markingDefNode.setLabel(tlp != null ? tlp : definitionType);
                                        markingDefNode.setData(hit.getSource());
                                        contextData.addNode(markingDefNode);
                                        //Add Edge
                                        Edge markingDefEdge = new Edge();
                                        markingDefEdge.setId("auto-generated".concat(UUID.randomUUID().toString()));
                                        markingDefEdge.setSource(node.getId());
                                        markingDefEdge.setTarget(markingDefId);
                                        Map<String, Object> edgeData = new HashMap<>();
                                        edgeData.put("tlp", tlp);
                                        markingDefNode.setData(edgeData);
                                        contextData.addEdge(markingDefEdge);
                                    }

                                }
                            }


                        }
                    }catch (Exception e) {
                        e.printStackTrace();
                        //TODO Handle gracefully
                    }


                }
                //Next Look for granular markings
                List<Map> granularMarkings = (List<Map>)data.get("granular_markings");
                if(granularMarkings != null) {
                    markingIds = new ArrayList<>();
                    Map<String, List<String>> markingToFieldMap = new HashMap<>();
                    for(Map granularMarking: granularMarkings) {
                        markingIds.add((String)granularMarking.get("marking_ref"));
                        markingToFieldMap.put((String)granularMarking.get("marking_ref") , (List<String>)granularMarking.get("selectors"));
                    }
                    Set<String> markingIdSet = new HashSet<>(markingIds);
                    List<String> fieldsToReturn = new ArrayList<>();
                    fieldsToReturn.add("definition.tlp");
                    String[] indexNames = new String[1];
                    indexNames[0] = "intel";
                    SearchHits hits = esIndex.termQuery("id", markingIdSet, indexNames, fieldsToReturn.toArray(new String[0]), "marking-definition");
                    for(SearchHit hit: hits) {
                        String markingId = hit.getId();

                        String tlp = (String)((HashMap)hit.getSource().get("definition")).get("tlp");
                        if(value(tlp) > value(filterCriteria)) {
                            //Remove the fileds from the source
                            List<String> fieldsToRemove = markingToFieldMap.get(markingId);
                            for(String field : fieldsToRemove) {
                                if(field.contains("[") && field.endsWith("]")) {
                                    //We only need to remove a specific value from the field.
                                    //Get the field Name
                                    String fieldName = field.substring(0, field.indexOf("[")-1);
                                    List values = (List)node.getData().get(fieldName);
                                    List copyOfList = fieldToNewValuesMap.get(fieldName);
                                    if(copyOfList == null || copyOfList.isEmpty()) {
                                        copyOfList = cloneItemList(values);
                                    }


                                    String indexStr = field.substring(field.indexOf("[")+1, field.indexOf("]"));
                                    String value = (String)values.get(Integer.valueOf(indexStr).intValue());

                                    copyOfList.remove(value);
                                    fieldToNewValuesMap.put(fieldName, copyOfList);

//                            node.getData().put(fieldName, values);
//                            values.remove(getIndex)
                                } else {
                                    //we should remove the entire field.
                                    node.getData().remove(field);
                                }
                            }
//                    node.getData().remove()

                        } else {
                            String markingDefId = (String) hit.getSource().get("id");
                            String definitionType = (String) hit.getSource().get("definition_type");
                            //Add a marking definition node and an edge from the node to the marking definition
                            if(!contextData.isNodePresent(markingDefId)) {
                                Node markingDefNode = new Node();
                                markingDefNode.setId(markingDefId);
                                markingDefNode.setType(tlp != null ? tlp : definitionType);
                                markingDefNode.setLabel(tlp != null ? tlp : definitionType);
                                markingDefNode.setData(hit.getSource());
                                contextData.addNode(markingDefNode);
                                //Add Edge
                                Edge markingDefEdge = new Edge();
                                markingDefEdge.setId("auto-generated".concat(UUID.randomUUID().toString()));
                                markingDefEdge.setSource(node.getId());
                                markingDefEdge.setTarget(markingDefId);
                                Map<String, Object> edgeData = new HashMap<>();
                                edgeData.put("tlp", tlp);
                                markingDefNode.setData(edgeData);
                                contextData.addEdge(markingDefEdge);
                            }
                        }

                    }
                }

//            System.out.println(granularMarkings);


                for(String key: fieldToNewValuesMap.keySet()) {
                    node.getData().put(key, fieldToNewValuesMap.get(key));
                }
                if(node.getData().containsKey("granular_markings")) {
                    node.getData().remove("granular_markings");
                }
                if(node.getData().containsKey("object_marking_refs")) {
                    node.getData().remove("object_marking_refs");
                }


            }

            contextData.getNodes().removeAll(nodesToRemove);
            List<Edge> listOfEdgesToRemove = new ArrayList<>();
            //TODO: Also remove the edges that have the removed node as source or target ref
            for(Edge edge : contextData.getEdges()) {
                if(nodeIdsToRemove.contains(edge.getSource())) {
                    listOfEdgesToRemove.add(edge);
                }else if(nodeIdsToRemove.contains(edge.getTarget())) {
                    listOfEdgesToRemove.add(edge);
                }
            }
            contextData.getEdges().removeAll(listOfEdgesToRemove);

        }catch(Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }


    }



    private Integer value(String tlp) {
        if(tlp == null) {
            return 0;
        }else if(tlp.equalsIgnoreCase("WHITE")) {
            return 1;
        }else if(tlp.equalsIgnoreCase("AMBER")) {
            return 2;
        }else if(tlp.equalsIgnoreCase("GREEN")) {
            return 3;
        }else if(tlp.equalsIgnoreCase("RED")) {
            return 4;
        }else if(tlp.equalsIgnoreCase("BLACK")) {
            return 5;
        }
        return null;
    }

    private List<String> cloneItemList(List<String> items)
    {
        String[] itemArray = new String[items.size()];
        itemArray = items.toArray(itemArray);
        return new ArrayList<>(Arrays.asList(itemArray));
    }
}
