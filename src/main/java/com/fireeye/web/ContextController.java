package com.fireeye.web;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fireeye.service.ContextService;
import com.fireeye.service.Filter;
import com.fireeye.service.IngestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Created by LT-Mac-Akumar on 07/07/2017.
 */
@RestController
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:3001"})
public class ContextController {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private ContextService service;

    @Autowired
    private List<Filter> filters;

    @Autowired
    private IngestService ingestService;

    @RequestMapping(value = "/context", produces = MediaType.APPLICATION_JSON_VALUE)
    public ContextData get(@RequestParam(value = "query")String query, @RequestParam(value = "tlp", defaultValue = "white")String tlp) {
        ContextData data =  service.getData(query);
        for(Filter filter: filters) {
            filter.filter(data, tlp);
        }
        return data;

    }

    @RequestMapping(value = "/report/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ContextData getReport(@PathVariable("id") String id, @RequestParam(value = "tlp", defaultValue = "white")String tlp) {
        ContextData data =  service.getReportData(id);
        for(Filter filter: filters) {
            filter.filter(data, tlp);
        }
        return data;
    }

    @RequestMapping(value = "/indicators", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<Integer,Map<String, Object>> getIndicators(@RequestParam(value = "ind-type")String indicatorType) {
        return service.getIndicators(indicatorType);

    }

    @RequestMapping(value = "/ingest/stix", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public List<String> ingestStix(@RequestBody String json) throws Exception{
        return ingestService.ingestStix(json);
    }

    @RequestMapping(value = "/ingest/cve", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public List<String> ingestCVE(@RequestBody String json) throws Exception{
        return ingestService.ingestCVE(json);
    }

    @RequestMapping(value = "/ingest/cpe", method = RequestMethod.POST, consumes = MediaType.APPLICATION_XML_VALUE)
    public List<String> ingestCPE(@RequestBody String xml) throws Exception{
        return ingestService.ingestCPE(xml);
    }

//    @RequestMapping(value = "/ingest/stix1", method = RequestMethod.POST, consumes = MediaType.APPLICATION_XML_VALUE)
//    public List<String> ingestStix1(@RequestBody String xml) throws Exception{
//        return ingestService.ingestStix1(xml);
//    }

    @RequestMapping(value = "/relationship/data", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
    public HttpStatus addRelationshipData(@RequestBody String jsonBody) throws IOException{
        Map values = objectMapper.readValue(jsonBody, Map.class);
        if((values.containsKey("id")))
            return HttpStatus.OK;
        else
            return HttpStatus.BAD_REQUEST;
    }

    @RequestMapping(value = "/node", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
    public HttpStatus deleteNode(@RequestBody String jsonBody) throws IOException {
        Map values = objectMapper.readValue(jsonBody, Map.class);
        if((values.containsKey("id")))
            return HttpStatus.OK;
        else
            return HttpStatus.BAD_REQUEST;

    }

    @RequestMapping(value = "/relationship", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public HttpStatus addRelationship(@RequestBody String jsonBody) throws IOException {
        Map values = objectMapper.readValue(jsonBody, Map.class);
        if(values.containsKey("relationship_type") && values.containsKey("source_ref") && values.containsKey("target_ref"))
            return HttpStatus.CREATED;
        else
            return HttpStatus.BAD_REQUEST;
    }


    @RequestMapping(value = "/relationship", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
    public HttpStatus updateRelationship(@RequestBody String jsonBody) throws IOException{
        Map values = objectMapper.readValue(jsonBody, Map.class);
        if((values.containsKey("id")) && values.containsKey("relationship_type") && values.containsKey("source_ref") && values.containsKey("target_ref"))
            return HttpStatus.OK;
        else
            return HttpStatus.BAD_REQUEST;
    }

    @RequestMapping(value = "/relationship/{id}", method = RequestMethod.DELETE)
    public HttpStatus deleteRelationship(@PathVariable(value = "id") String id) throws IOException{
        if(id != null && !id.isEmpty()) {
            return HttpStatus.OK;
        } else {
            return HttpStatus.BAD_REQUEST;
        }
    }

}
