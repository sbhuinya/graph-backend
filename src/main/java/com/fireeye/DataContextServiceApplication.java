package com.fireeye;

import com.fireeye.service.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@Configuration
public class DataContextServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(DataContextServiceApplication.class, args);
	}


	@Bean
	public ContextService service() {
		ContextService service = new ContextService();
		service.setEsIndex(esIndex());
		List<Filter> filters = new ArrayList<>();
		filters.add(tlpFilter());
		return service;
	}

	@Bean
	public IngestService ingestService() throws Exception{
		IngestService iserv = new IngestService();
		iserv.setEsIndex(esIndex());
		return iserv;

	}

	@Bean
	public ESIndex esIndex() {
		ESSettings esSettings = new ESSettings();
		esSettings = esSettings.builder().clusterName("elasticsearch")
				.hostAndPort("localhost", 9300)
				.indexName("intel").build();
		ESIndex index = new ESIndex(esSettings);

		return index;
	}

	public Filter tlpFilter() {
		TLPFilter filter = new TLPFilter();
        filter.setEsIndex(esIndex());
		return filter;
	}

    @Bean
    public List<Filter> filters() {
        List<Filter> filters= new ArrayList<>();
        filters.add(tlpFilter());
        return filters;
    }


}
