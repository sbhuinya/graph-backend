package com.fireeye.web;

import com.fireeye.service.IngestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Created by LT-Mac-Akumar on 04/08/2017.
 */
@RestController
public class IngestController {

    @Autowired
    private IngestService ingestService;


    /**
     * Ingest Stix data
     * @param xml
     * @return
     * @throws Exception
     */
    @RequestMapping(value = "/ingest/stix1", method = RequestMethod.POST, consumes = MediaType.APPLICATION_XML_VALUE)
    public List<String> ingestStix1(@RequestBody String xml) throws Exception{
        return ingestService.ingestStix1(xml);
    }
}
