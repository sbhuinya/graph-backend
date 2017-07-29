package com.fireeye.service;

/**
 * Created by LT-Mac-Akumar on 13/07/2017.
 */
public interface Filter<DATA, CRITERIA> {

    void filter(DATA data, CRITERIA filterCriteria);
}
