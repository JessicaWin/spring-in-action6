package com.jessica.taco.client.service;

import java.io.IOException;
import java.util.Arrays;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;
import com.jessica.taco.client.entity.Ingredient;

public class RestIngredientService implements IngredientService {
  private RestTemplate restTemplate;

  public RestIngredientService(String accessToken) {
    this.restTemplate = new RestTemplate();
    if (accessToken != null) {
      this.restTemplate.getInterceptors().add(getBearerTokenInterceptor(accessToken));
    }
  }

  private ClientHttpRequestInterceptor getBearerTokenInterceptor(String accessToken) {
    ClientHttpRequestInterceptor interceptor = new ClientHttpRequestInterceptor() {
      @Override
      public ClientHttpResponse intercept(HttpRequest request, byte[] bytes,
          ClientHttpRequestExecution execution) throws IOException {
        request.getHeaders().add("Authorization", "Bearer " + accessToken);
        return execution.execute(request, bytes);
      }
    };
    return interceptor;
  }


  public Iterable<Ingredient> findAll() {
    return Arrays.asList(
        restTemplate.getForObject("http://localhost:8080/api/ingredients", Ingredient[].class));
  }

  public Ingredient addIngredient(Ingredient ingredient) {
    return restTemplate.postForObject("http://localhost:8080/api/ingredients", ingredient,
        Ingredient.class);
  }
}
