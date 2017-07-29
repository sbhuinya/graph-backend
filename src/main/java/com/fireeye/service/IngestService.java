package com.fireeye.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by LT-Mac-Akumar on 13/07/2017.
 */
@Component
public class IngestService {

    @Autowired
    private ESIndex esIndex;

    public IngestService() throws NoSuchAlgorithmException {
    }

    public ESIndex getEsIndex() {
        return esIndex;
    }

    public void setEsIndex(ESIndex esIndex) {
        this.esIndex = esIndex;
    }

    MessageDigest digest = MessageDigest.getInstance("SHA-256");

    private final ObjectMapper mapper = new ObjectMapper();

    public List<String> ingestCPE(String xml) throws Exception{
        List<String> cpeIndexed = new ArrayList<>();
        XmlMapper xmlMapper = new XmlMapper();
        List<LinkedHashMap> node = xmlMapper.readValue(xml, List.class);

        ObjectMapper jsonMapper = new ObjectMapper();
        String json = jsonMapper.writeValueAsString(node);
        List<LinkedHashMap<String, Object>> cpeList = (List)mapper.readValue(json, List.class);

        for(Map item: cpeList) {
            if(isCPEItem(item)) {
                String id = "cpe--".concat(getSHA256Hash((String)item.get("name")));
                item.put("id", id);
                item.put("type", "cpe");
                replaceEmptyWithDefaultKeys(item);

                cpeIndexed.add(esIndex.upsertDocument("nvd", "cpe", id, mapper.writeValueAsBytes(item)));
            }

        }
        return cpeIndexed;
    }

//    public List<String> ingestStix1(String xml) throws Exception {
//        STIXPackage stixPackage = STIXPackage.fromXMLString(xml);
//        if(stixPackage.getIndicators() != null && stixPackage.getIndicators().getIndicators() != null) {
//            List<IndicatorBaseType> indicators = stixPackage
//                    .getIndicators().getIndicators();
//            List<MarkingSpecificationType> handling = stixPackage.getSTIXHeader().getHandling().getMarkings();
//            for(MarkingSpecificationType marking: handling) {
//                ObjectMapper jsonMapper = new ObjectMapper();
//                String json = jsonMapper.writeValueAsString(marking);
//                System.out.println(json);
//            }
//            for(IndicatorBaseType indicator: indicators) {
//                ObjectMapper jsonMapper = new ObjectMapper();
//                jsonMapper.
//                String json = jsonMapper.writeValueAsString(indicator);
//                System.out.println(json);
//                indicator = (Indicator)indicator;
////                indicator.get
//            }
//        }
//    return null;
//
//    }
    private void replaceEmptyWithDefaultKeys(Map<String, Object> item) {
        Map<String, Object> valuesToReplace = new HashMap();
        for(String key: item.keySet()) {
            Object value = item.get(key);
            if(key.equals("")) {
                valuesToReplace.put("value", value);
                item.remove(key);
            }
            if(value instanceof Map) {
                replaceEmptyWithDefaultKeys((Map<String, Object>) value);
            }
        }
        item.putAll(valuesToReplace);
    }

    private Boolean isCPEItem(Map item) {
        if(item != null && !item.containsKey("schemaLocation") && !item.containsKey("product_name")) {
            return true;
        }else
            return false;
    }

    private String getSHA256Hash(String value) throws Exception{

        byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public List<String> ingestCVE(String json) throws Exception{

        LinkedHashMap<String, Object> cveBundle = (LinkedHashMap<String, Object>)mapper.readValue(json, Object.class);
        List<LinkedHashMap> cveItems = (List<LinkedHashMap>)cveBundle.get("CVE_Items");
        List<String> documentsAdded = new ArrayList<>();
        for(LinkedHashMap cve: cveItems) {
            LinkedHashMap cveObject = (LinkedHashMap) cve.get("cve");

            LinkedHashMap cveMeta = (LinkedHashMap)cveObject.get("CVE_data_meta");

            String cveId = (String)cveMeta.get("ID");
            cveObject.put("id", cveId);
            cveObject.remove("CVE_data_meta");

            cveObject.put("publishedDate", cve.get("publishedDate"));
            cveObject.put("lastModifiedDate", cve.get("lastModifiedDate"));

            //Manage Affects Relationship with vendor objects
            LinkedHashMap affects = (LinkedHashMap)cveObject.get("affects");
            List<Map> vendorDataList = (List<Map>)((Map)affects.get("vendor")).get("vendor_data");
            for(Map vendorData: vendorDataList) {
                String vendorName = vendorData.get("vendor_name").toString();
                String vendorId = "vendor--".concat(vendorName).concat("--").concat(cveId);
                Map product = (Map)vendorData.get("product");
                List<Map> productDataList = (List<Map>)product.get("product_data");
                for(Map productData: productDataList) {
                    String productId = "product--".concat(vendorName).concat("--").concat(productData.get("product_name").toString()).concat("--").concat(cveId);
                    productData.put("id", productId);
                    productData.put("type", "product");
                    esIndex.upsertDocument("nvd", "product", productId, mapper.writeValueAsBytes(productData));
                    Relationship affectedProductRelationship = new Relationship(vendorId, productId, "affected-product");
                    esIndex.upsertDocument("relationship", "relationship", affectedProductRelationship.getId(), mapper.writeValueAsBytes(affectedProductRelationship));
                }

                vendorData.put("id", vendorId);
                vendorData.put("type", "vendor");
                vendorData.remove("product");
                esIndex.upsertDocument("nvd", "vendor", vendorId ,mapper.writeValueAsBytes(vendorData));
                Relationship affectsRelationship = new Relationship(cveId, vendorId, "affects");
                esIndex.upsertDocument("relationship", "relationship", affectsRelationship.getId(), mapper.writeValueAsBytes(affectsRelationship));

                //Get Product

            }
            cveObject.remove("affects");
            cveObject.put("type", "cve");


            esIndex.upsertDocument("nvd","cve", cveId, mapper.writeValueAsBytes(cveObject));

            LinkedHashMap configuration = (LinkedHashMap)cve.get("configurations");
            String configId = "configuration--".concat(cveId);
            configuration.put("id", configId);
            configuration.put("type", "configuration");
            esIndex.upsertDocument("nvd", "configuration", configId, mapper.writeValueAsBytes(configuration));

            LinkedHashMap impact = (LinkedHashMap)cve.get("impact");
            String impactId = "impact--".concat(cveId);
            impact.put("id", impactId);
            esIndex.upsertDocument("nvd", "impact", impactId, mapper.writeValueAsBytes(impact));

            Relationship configRelationship = new Relationship(cveId, configId, "related-config");
            esIndex.upsertDocument("relationship", "relationship", configRelationship.getId(), mapper.writeValueAsBytes(configRelationship));

            Relationship impactRelationship = new Relationship(cveId, impactId, "related-impact");
            esIndex.upsertDocument("relationship", "relationship", configRelationship.getId(), mapper.writeValueAsBytes(impactRelationship));

            documentsAdded.add(cveId);
        }
        return documentsAdded;
    }

    public List<String> ingestStix(String jsonData) throws Exception{

        LinkedHashMap<String, Object> stixBundle = (LinkedHashMap<String, Object>)mapper.readValue(jsonData, Object.class);
        List objects = (List)stixBundle.get("objects");
        List<String> documentsAdded = new ArrayList<>();
        for(Object object : objects) {
            byte[] individualObject = mapper.writeValueAsBytes(object);
            Map map = (Map)object;
            String type = (String)map.get("type");
            String id = (String)map.get("id");

            if(type.equals("relationship")) {
                documentsAdded.add(esIndex.upsertDocument("relationship", type, id, individualObject));
            } else {
                documentsAdded.add(esIndex.upsertDocument("intel", type, id, individualObject));
            }

        }
        return documentsAdded;



    }

    public String createRelationship(String json) throws Exception{

        LinkedHashMap<String, Object> relationship = (LinkedHashMap<String, Object>)mapper.readValue(json, Object.class);
        String sourceRef = (String)relationship.get("source_ref");
        String destRef = (String)relationship.get("target_ref");
        String relationshipType = (String)relationship.get("relationship_type");
        relationship.put("type", "relationship");
        relationship.put("created", new Date());
        relationship.put("modified", new Date());

        //Make sure that the source and target nodes exists
        if(!esIndex.documentExists(null, sourceRef)) {
            throw new RuntimeException("Trying to create a relationship for a Node that does not exists:" + sourceRef);
        }
        if(!esIndex.documentExists(null, destRef)) {
            throw new RuntimeException("Trying to create a relationship for a Node that does not exists:" + destRef);
        }

//        String existsQuery = "type:relationship AND source_ref:".concat(sourceRef).concat(" AND target_ref:").concat(destRef).concat(" AND relationship_type:").concat(relationshipType);
//        SearchHits hits = esIndex.query(existsQuery);
//        if(hits.getHits().length > 0) {
//            throw new RuntimeException("Relationship already exists");
//        }

        String relationshipId = "relationship--".concat(UUID.randomUUID().toString());
        return esIndex.upsertDocument("relationship", "relationship", relationshipId, mapper.writeValueAsBytes(relationship));
    }

    public static void main(String[] args) throws Exception{
        String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" +
                "<cpe-list xmlns:config=\"http://scap.nist.gov/schema/configuration/0.1\" xmlns=\"http://cpe.mitre.org/dictionary/2.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.3\" xmlns:cpe-23=\"http://scap.nist.gov/schema/cpe-extension/2.3\" xmlns:ns6=\"http://scap.nist.gov/schema/scap-core/0.1\" xmlns:meta=\"http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2\" xsi:schemaLocation=\"http://cpe.mitre.org/dictionary/2.0 https://scap.nist.gov/schema/cpe/2.2/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 https://scap.nist.gov/schema/cpe/2.1/cpe-dictionary-metadata_0.2.xsd http://scap.nist.gov/schema/scap-core/0.3 https://scap.nist.gov/schema/nvd/scap-core_0.3.xsd http://scap.nist.gov/schema/configuration/0.1 https://scap.nist.gov/schema/nvd/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 https://scap.nist.gov/schema/nvd/scap-core_0.1.xsd\">\n" +
                "  <generator>\n" +
                "    <product_name>National Vulnerability Database (NVD)</product_name>\n" +
                "    <product_version>3.7</product_version>\n" +
                "    <schema_version>2.2</schema_version>\n" +
                "    <timestamp>2016-10-26T14:11:00.155Z</timestamp>\n" +
                "  </generator>\n" +
                "  <cpe-item name=\"cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~\">\n" +
                "    <title xml:lang=\"en-US\">$0.99 Kindle Books project $0.99 Kindle Books (aka com.kindle.books.for99) for android 6.0</title>\n" +
                "    <references>\n" +
                "      <reference href=\"https://play.google.com/store/apps/details?id=com.kindle.books.for99\">Product information</reference>\n" +
                "      <reference href=\"https://docs.google.com/spreadsheets/d/1t5GXwjw82SyunALVJb2w0zi3FoLRIkfGPc7AMjRF0r4/edit?pli=1#gid=1053404143\">Government Advisory</reference>\n" +
                "    </references>\n" +
                "    <meta:item-metadata nvd-id=\"289692\" status=\"FINAL\" modification-date=\"2014-11-10T17:01:25.103Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:0.7\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 0.7</title>\n" +
                "    <meta:item-metadata nvd-id=\"121218\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.197Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:1.2.5\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 1.2.5</title>\n" +
                "    <meta:item-metadata nvd-id=\"121219\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.240Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:1.3.1\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 1.3.1</title>\n" +
                "    <meta:item-metadata nvd-id=\"121214\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.273Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:1.4.1\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 1.4.1</title>\n" +
                "    <meta:item-metadata nvd-id=\"121215\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.320Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:1.4.2\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 1.4.2</title>\n" +
                "    <meta:item-metadata nvd-id=\"121216\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.350Z\"/>\n" +
                "  </cpe-item>\n" +
                "  <cpe-item name=\"cpe:/a:1024cms:1024_cms:1.4.2:beta\">\n" +
                "    <title xml:lang=\"en-US\">1024cms.org 1024 CMS 1.4.2 beta</title>\n" +
                "    <meta:item-metadata nvd-id=\"121217\" status=\"FINAL\" modification-date=\"2010-12-14T19:38:32.397Z\"/>\n" +
                "  </cpe-item>\n" +
                "</cpe-list>";
        IngestService service = new IngestService();
        service.ingestCPE(xml);
    }
}
