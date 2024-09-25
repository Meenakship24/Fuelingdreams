import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CropperDialoComponent } from './cropper-dialo.component';

describe('CropperDialoComponent', () => {
  let component: CropperDialoComponent;
  let fixture: ComponentFixture<CropperDialoComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CropperDialoComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CropperDialoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
