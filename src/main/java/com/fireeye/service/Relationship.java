package com.fireeye.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;

/**
 * Created by LT-Mac-Akumar on 17/07/2017.
 */
public class Relationship {

    private String type;

    private String id;

    private Date created;

    private Date modified;

    private String relationship_type;

    private String source_ref;

    private String target_ref;

    public Relationship() {
        this.type = "relationship";
        this.created = new Date();
        this.modified = new Date();
    }
    public Relationship(String source_ref, String target_ref, String relationship_type) throws Exception{
        this.type = "relationship";
        this.created = new Date();
        this.modified = new Date();
        if(source_ref == null || source_ref.isEmpty()) {
            throw new RuntimeException("source ref in a relationship cannot be null or empty.");
        }
        this.source_ref = source_ref;
        if(target_ref == null || target_ref.isEmpty()) {
            throw new RuntimeException("Target ref in a relationship cannot be null or empty.");
        }
        this.target_ref = target_ref;
        if(relationship_type == null || relationship_type.isEmpty()) {
            throw new RuntimeException("Relationship type in a relationship cannot be null or empty.");
        }
        this.relationship_type = relationship_type;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String digestString = source_ref.concat(target_ref).concat(relationship_type);
        byte[] hash = digest.digest(digestString.getBytes(StandardCharsets.UTF_8));

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
        }
        this.id = "relationship--".concat(sb.toString());
    }

    public static void main(String[] args) throws Exception{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String str1 = "source--1234".concat("target--67676767").concat("relationship-type-666555444");
        String str2 = "target--67676767".concat("source--1234").concat("relationship-type-666555444");
        byte[] hash1 = digest.digest(str1.getBytes(StandardCharsets.UTF_8));
        byte[] hash2 = digest.digest(str2.getBytes(StandardCharsets.UTF_8));
        String newValue1 = new String(hash1);
        String newValue2 = new String(hash2);

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < hash1.length; i++) {
            sb.append(Integer.toString((hash1[i] & 0xff) + 0x100, 16).substring(1));
        }

        StringBuffer sb1 = new StringBuffer();
        for (int i = 0; i < hash2.length; i++) {
            sb1.append(Integer.toString((hash2[i] & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println(sb.toString().equals(sb1.toString()));
        System.out.println(sb.toString());
        System.out.println(sb1.toString());
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getId() throws Exception{
        if(id != null) {
            return id;
        }
        if(source_ref == null || source_ref.isEmpty()) {
            throw new RuntimeException("source ref in a relationship cannot be null or empty.");
        }

        if(target_ref == null || target_ref.isEmpty()) {
            throw new RuntimeException("Target ref in a relationship cannot be null or empty.");
        }

        if(relationship_type == null || relationship_type.isEmpty()) {
            throw new RuntimeException("Relationship type in a relationship cannot be null or empty.");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String digestString = source_ref.concat(target_ref).concat(relationship_type);
        byte[] hash = digest.digest(digestString.getBytes(StandardCharsets.UTF_8));

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
        }
        this.id = "relationship--".concat(sb.toString());
        return id;
    }


    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getModified() {
        return modified;
    }

    public void setModified(Date modified) {
        this.modified = modified;
    }

    public String getRelationship_type() {
        return relationship_type;
    }

    public void setRelationship_type(String relationship_type) {
        this.relationship_type = relationship_type;
    }

    public String getSource_ref() {
        return source_ref;
    }

    public void setSource_ref(String source_ref) {
        this.source_ref = source_ref;
    }

    public String getTarget_ref() {
        return target_ref;
    }

    public void setTarget_ref(String target_ref) {
        this.target_ref = target_ref;
    }
}
