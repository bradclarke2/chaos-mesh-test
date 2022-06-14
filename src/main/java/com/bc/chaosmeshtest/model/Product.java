package com.bc.chaosmeshtest.model;

import org.springframework.data.annotation.Id;

public record Product (@Id String id, String description) {}
